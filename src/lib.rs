use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Once};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

static RUSTLS_INIT: Once = Once::new();

fn init_rustls() {
    RUSTLS_INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    });
}

#[cfg(feature = "own-cert-list")]
mod own_certs {
    include!(env!("TINY_HTTP_CLIENT_OWN_CERTS"));
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn as_bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Simple HTTP GET request.
pub fn get(url: &str) -> Result<Response, Box<dyn std::error::Error>> {
    get_with_headers(url, &[])
}

/// HTTP GET request with custom headers.
///
/// Example:
///
/// get_with_headers(
///     "https://example.com/",
///     &[("User-Agent", "my-client")],
/// )?;
pub fn get_with_headers(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    init_rustls();

    get_redirect(url, headers, 0)
}

fn get_redirect(
    url: &str,
    headers: &[(&str, &str)],
    redirect_count: usize,
) -> Result<Response, Box<dyn std::error::Error>> {
    if redirect_count > MAX_REDIRECTS {
        return Err("too many HTTP redirects".into());
    }

    let parsed_url = parse_url(url)?;

    let response = if parsed_url.https {
        get_https(&parsed_url, headers)?
    } else {
        get_http(&parsed_url, headers)?
    };

    /*
     * GitHub uses redirects when downloading release assets.
     *
     * We follow all standard HTTP redirects:
     *
     * 301 Moved Permanently
     * 302 Found
     * 303 See Other
     * 307 Temporary Redirect
     * 308 Permanent Redirect
     */
    match response.status {
        301 | 302 | 303 | 307 | 308 => {
            if let Some(location) = response.header("Location") {
                let next_url = resolve_redirect(&parsed_url, location)?;

                return get_redirect(&next_url, headers, redirect_count + 1);
            }
        }
        _ => {}
    }

    if !(200..300).contains(&response.status) {
        return Err(format!("HTTP request failed: {}", response.status).into());
    }

    Ok(response)
}

struct ParsedUrl {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(input: &str) -> Result<ParsedUrl, Box<dyn std::error::Error>> {
    let (https, rest) = if let Some(rest) = input.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = input.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!("unsupported URL: {}", input).into());
    };

    let (authority, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };

    let (host, port) = if let Some(host_part) = authority.strip_prefix('[') {
        let end = host_part.find(']').ok_or("invalid IPv6 address")?;

        let host = &host_part[..end];

        let port = host_part
            .get(end + 1..)
            .and_then(|s| s.strip_prefix(':'))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(if https { 443 } else { 80 });

        (host.to_string(), port)
    } else {
        match authority.rfind(':') {
            Some(pos) if authority[pos + 1..].parse::<u16>().is_ok() => {
                (authority[..pos].to_string(), authority[pos + 1..].parse()?)
            }

            _ => (authority.to_string(), if https { 443 } else { 80 }),
        }
    };

    Ok(ParsedUrl {
        https,
        host,
        port,
        path: path.to_string(),
    })
}

fn get_http(
    url: &ParsedUrl,
    headers: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", url.host, url.port);

    let socket_addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or("failed to resolve host")?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT)?;

    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;

    write_request(&mut stream, &url.host, &url.path, headers)?;

    read_response(&mut stream)
}

fn get_https(
    url: &ParsedUrl,
    headers: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", url.host, url.port);

    let socket_addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or("failed to resolve host")?;

    let tcp = TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT)?;

    tcp.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    tcp.set_write_timeout(Some(CONNECT_TIMEOUT))?;

    let root_store = load_root_certificates()?;

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    /*
     * ServerName owns the hostname.
     *
     * rustls requires an owned value with a 'static lifetime
     * for ClientConnection.
     */
    let server_name = ServerName::try_from(url.host.clone())?;

    let connection = ClientConnection::new(Arc::new(config), server_name)?;

    let mut stream = StreamOwned::new(connection, tcp);

    write_request(&mut stream, &url.host, &url.path, headers)?;

    read_response(&mut stream)
}

fn load_root_certificates(
) -> Result<RootCertStore, Box<dyn std::error::Error>> {
    let mut root_store = RootCertStore::empty();

    #[cfg(feature = "own-cert-list")]
    {
        for cert in own_certs::load() {
            root_store.add(cert)?;
        }
    }

    #[cfg(all(
        not(feature = "own-cert-list"),
        not(target_os = "windows")
    ))]
    {
        use webpki_roots::TLS_SERVER_ROOTS;

        root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    }

    #[cfg(all(
        not(feature = "own-cert-list"),
        target_os = "windows"
    ))]
    {
        let result = rustls_native_certs::load_native_certs();

        for cert in result.certs {
            root_store.add(cert)?;
        }

        if root_store.is_empty() {
            return Err("no native root certificates found".into());
        }
    }

    Ok(root_store)
}

fn write_request<S: Write>(
    stream: &mut S,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(), Box<dyn std::error::Error>> {
    write!(
        stream,
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: peers_updater\r\n\
         Accept: */*\r\n\
         Connection: close\r\n",
        path, host
    )?;

    for (name, value) in headers {
        /*
         * Don't allow callers to accidentally inject CR/LF
         * into the HTTP request.
         */
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            return Err("invalid HTTP header".into());
        }

        write!(stream, "{}: {}\r\n", name, value)?;
    }

    write!(stream, "\r\n")?;

    stream.flush()?;

    Ok(())
}

fn read_response<R: Read>(stream: &mut R) -> Result<Response, Box<dyn std::error::Error>> {
    let mut data = Vec::new();

    stream.read_to_end(&mut data)?;

    let header_end = find_header_end(&data).ok_or("invalid HTTP response: headers not found")?;

    let header_bytes = &data[..header_end];

    let raw_body = &data[header_end + 4..];

    let header_text = std::str::from_utf8(header_bytes)?;

    let mut lines = header_text.split("\r\n");

    let status_line = lines
        .next()
        .ok_or("invalid HTTP response: status line missing")?;

    let mut status_parts = status_line.splitn(3, ' ');

    let _http_version = status_parts.next().ok_or("invalid HTTP status line")?;

    let status = status_parts
        .next()
        .ok_or("invalid HTTP status line")?
        .parse::<u16>()?;

    let mut headers = Vec::new();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_string();
            let value = line[pos + 1..].trim().to_string();

            headers.push((key, value));
        }
    }

    /*
     * HTTP/1.1 chunked transfer encoding.
     *
     * Example:
     *
     * 4\r\n
     * Wiki\r\n
     * 5\r\n
     * pedia\r\n
     * 0\r\n
     * \r\n
     *
     * The chunk size is hexadecimal and is not part of the
     * actual response body.
     */
    let body = if headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("Transfer-Encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    }) {
        decode_chunked(raw_body)?
    } else {
        raw_body.to_vec()
    };

    Ok(Response {
        status,
        headers,
        body,
    })
}

fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut body = Vec::new();
    let mut pos = 0;

    loop {
        /*
         * Find the end of the chunk-size line.
         */
        let line_end =
            find_crlf(&data[pos..]).ok_or("invalid chunked response: chunk size not found")?;

        let size_line = &data[pos..pos + line_end];

        /*
         * Ignore optional chunk extensions:
         *
         * 4;foo=bar
         *
         * Only the part before ';' is the hexadecimal size.
         */
        let size_text = match size_line.iter().position(|&b| b == b';') {
            Some(index) => &size_line[..index],
            None => size_line,
        };

        let size_text = std::str::from_utf8(size_text)?.trim();

        let chunk_size = usize::from_str_radix(size_text, 16).map_err(|_| "invalid chunk size")?;

        pos += line_end + 2;

        /*
         * Zero-sized chunk marks the end of the body.
         */
        if chunk_size == 0 {
            /*
             * A chunked response may contain trailer headers
             * after the final zero-sized chunk.
             *
             * We don't need them, so simply stop here.
             */
            return Ok(body);
        }

        /*
         * Make sure the complete chunk is available.
         */
        let chunk_end = pos.checked_add(chunk_size).ok_or("chunk size overflow")?;

        if chunk_end > data.len() {
            return Err("invalid chunked response: incomplete chunk".into());
        }

        body.extend_from_slice(&data[pos..chunk_end]);

        pos = chunk_end;

        /*
         * Every chunk-data section must be followed by CRLF.
         */
        if data.len() < pos + 2 || data[pos] != b'\r' || data[pos + 1] != b'\n' {
            return Err("invalid chunked response: missing CRLF".into());
        }

        pos += 2;
    }
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn resolve_redirect(
    current: &ParsedUrl,
    location: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let location = location.trim();

    /*
     * Absolute URL:
     *
     * Location: https://objects.githubusercontent.com/...
     */
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }

    /*
     * Protocol-relative URL:
     *
     * Location: //objects.githubusercontent.com/...
     */
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!(
            "{}://{}",
            if current.https { "https" } else { "http" },
            rest
        ));
    }

    /*
     * Absolute path:
     *
     * Location: /foo/bar
     */
    if location.starts_with('/') {
        return Ok(format!(
            "{}://{}:{}{}",
            if current.https { "https" } else { "http" },
            current.host,
            current.port,
            location
        ));
    }

    /*
     * Relative path:
     *
     * Location: foo/bar
     */
    let base_path = match current.path.rfind('/') {
        Some(pos) => &current.path[..pos + 1],
        None => "/",
    };

    Ok(format!(
        "{}://{}:{}{}{}",
        if current.https { "https" } else { "http" },
        current.host,
        current.port,
        base_path,
        location
    ))
}
