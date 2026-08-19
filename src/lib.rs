use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Once};
use std::time::Duration;

use rustls::{
    ClientConfig,
    ClientConnection,
    RootCertStore,
    StreamOwned,
};
use rustls::pki_types::ServerName;
use webpki_roots::TLS_SERVER_ROOTS;

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

                return get_redirect(
                    &next_url,
                    headers,
                    redirect_count + 1,
                );
            }
        }
        _ => {}
    }

    if !(200..300).contains(&response.status) {
        return Err(format!(
            "HTTP request failed: {}",
            response.status
        )
        .into());
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
        let end = host_part
            .find(']')
            .ok_or("invalid IPv6 address")?;

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
                (
                    authority[..pos].to_string(),
                    authority[pos + 1..].parse()?,
                )
            }

            _ => (
                authority.to_string(),
                if https { 443 } else { 80 },
            ),
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

    let mut stream = TcpStream::connect_timeout(
        &socket_addr,
        CONNECT_TIMEOUT,
    )?;

    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;

    write_request(
        &mut stream,
        &url.host,
        &url.path,
        headers,
    )?;

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

    let tcp = TcpStream::connect_timeout(
        &socket_addr,
        CONNECT_TIMEOUT,
    )?;

    tcp.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    tcp.set_write_timeout(Some(CONNECT_TIMEOUT))?;

    let mut root_store = RootCertStore::empty();

    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());

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

    let connection = ClientConnection::new(
        Arc::new(config),
        server_name,
    )?;

    let mut stream = StreamOwned::new(connection, tcp);

    write_request(
        &mut stream,
        &url.host,
        &url.path,
        headers,
    )?;

    read_response(&mut stream)
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
        path,
        host
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

        write!(
            stream,
            "{}: {}\r\n",
            name,
            value
        )?;
    }

    write!(stream, "\r\n")?;

    stream.flush()?;

    Ok(())
}

fn read_response<R: Read>(
    stream: &mut R,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut data = Vec::new();

    stream.read_to_end(&mut data)?;

    let header_end = find_header_end(&data)
        .ok_or("invalid HTTP response: headers not found")?;

    let header_bytes = &data[..header_end];

    let body = data[header_end + 4..].to_vec();

    let header_text = std::str::from_utf8(header_bytes)?;

    let mut lines = header_text.split("\r\n");

    let status_line = lines
        .next()
        .ok_or("invalid HTTP response: status line missing")?;

    let mut status_parts = status_line.splitn(3, ' ');

    let _http_version = status_parts
        .next()
        .ok_or("invalid HTTP status line")?;

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

    Ok(Response {
        status,
        headers,
        body,
    })
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
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
    if location.starts_with("http://")
        || location.starts_with("https://")
    {
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
