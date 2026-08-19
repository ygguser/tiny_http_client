use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::{
    ClientConfig,
    ClientConnection,
    RootCertStore,
    StreamOwned,
};
use rustls_pki_types::ServerName;

const MAX_HEADER_SIZE: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 5;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidUrl,
    UnsupportedScheme,
    InvalidHost,
    InvalidPort,
    InvalidResponse,
    InvalidHeader,
    HttpStatus(u16),
    RedirectLimit,
    Tls(rustls::Error),
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => write!(f, "invalid URL"),
            Self::UnsupportedScheme => write!(f, "unsupported URL scheme"),
            Self::InvalidHost => write!(f, "invalid host"),
            Self::InvalidPort => write!(f, "invalid port"),
            Self::InvalidResponse => write!(f, "invalid HTTP response"),
            Self::InvalidHeader => write!(f, "invalid HTTP header"),
            Self::HttpStatus(code) => write!(f, "HTTP status {}", code),
            Self::RedirectLimit => write!(f, "too many redirects"),
            Self::Tls(e) => write!(f, "TLS error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}

enum Connection {
    Http(TcpStream),
    Https(StreamOwned<ClientConnection, TcpStream>),
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Http(stream) => stream.read(buf),
            Self::Https(stream) => stream.read(buf),
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Http(stream) => stream.write(buf),
            Self::Https(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Http(stream) => stream.flush(),
            Self::Https(stream) => stream.flush(),
        }
    }
}

struct Url<'a> {
    scheme: &'a str,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_url(url: &str) -> Result<Url<'_>> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err(Error::UnsupportedScheme);
    };

    let authority_end = rest
        .find(|c| matches!(c, '/' | '?' | '#'))
        .unwrap_or(rest.len());

    let authority = &rest[..authority_end];

    if authority.is_empty() {
        return Err(Error::InvalidHost);
    }

    let path = if authority_end < rest.len() {
        &rest[authority_end..]
    } else {
        "/"
    };

    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(Error::InvalidHost)?;

        let host = &authority[1..end];

        let port = if authority.len() > end + 1 {
            let port = authority
                .strip_prefix(&authority[..=end])
                .and_then(|s| s.strip_prefix(':'))
                .ok_or(Error::InvalidPort)?;

            port.parse().map_err(|_| Error::InvalidPort)?
        } else if scheme == "https" {
            443
        } else {
            80
        };

        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                let port = port.parse().map_err(|_| Error::InvalidPort)?;
                (host, port)
            }
            _ => {
                let port = if scheme == "https" { 443 } else { 80 };
                (authority, port)
            }
        }
    };

    if host.is_empty() {
        return Err(Error::InvalidHost);
    }

    Ok(Url {
        scheme,
        host,
        port,
        path,
    })
}

fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();

    roots.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn connect(url: &Url<'_>) -> Result<Connection> {
    let addr = format!("{}:{}", url.host, url.port);

    let tcp = TcpStream::connect(addr)?;

    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;

    if url.scheme == "http" {
        return Ok(Connection::Http(tcp));
    }

    let server_name =
        ServerName::try_from(url.host.to_owned())
            .map_err(|_| Error::InvalidHost)?;

    let connection = ClientConnection::new(
        tls_config(),
        server_name,
    )?;

    Ok(Connection::Https(
        StreamOwned::new(connection, tcp)
    ))
}

fn read_headers(stream: &mut Connection) -> Result<Vec<u8>> {
    let mut headers = Vec::with_capacity(4096);

    loop {
        let mut byte = [0u8; 1];

        let n = stream.read(&mut byte)?;

        if n == 0 {
            return Err(Error::InvalidResponse);
        }

        headers.push(byte[0]);

        if headers.len() > MAX_HEADER_SIZE {
            return Err(Error::InvalidResponse);
        }

        if headers.len() >= 4
            && &headers[headers.len() - 4..] == b"\r\n\r\n"
        {
            return Ok(headers);
        }
    }
}

fn parse_status(headers: &[u8]) -> Result<u16> {
    let line_end = headers
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(Error::InvalidResponse)?;

    let line = std::str::from_utf8(&headers[..line_end])
        .map_err(|_| Error::InvalidResponse)?;

    let mut parts = line.split_whitespace();

    let version = parts.next().ok_or(Error::InvalidResponse)?;

    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Error::InvalidResponse);
    }

    let status = parts
        .next()
        .ok_or(Error::InvalidResponse)?
        .parse()
        .map_err(|_| Error::InvalidResponse)?;

    Ok(status)
}

fn header_value<'a>(headers: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let name = name.as_bytes();

    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r")?;

        if let Some((key, value)) = line.split_once(&b':') {
            if key.eq_ignore_ascii_case(name) {
                return Some(value.strip_prefix(b" ").unwrap_or(value));
            }
        }
    }

    None
}

fn find_body_start(headers: &[u8]) -> usize {
    headers.len()
}

fn read_exact_amount(
    stream: &mut Connection,
    output: &mut Vec<u8>,
    mut remaining: usize,
) -> Result<()> {
    let mut buffer = [0u8; 8192];

    while remaining > 0 {
        let size = remaining.min(buffer.len());

        let n = stream.read(&mut buffer[..size])?;

        if n == 0 {
            return Err(Error::InvalidResponse);
        }

        output.extend_from_slice(&buffer[..n]);

        remaining -= n;
    }

    Ok(())
}

fn read_chunked(
    stream: &mut Connection,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut line = Vec::with_capacity(32);

    loop {
        line.clear();

        loop {
            let mut byte = [0u8; 1];

            if stream.read(&mut byte)? == 0 {
                return Err(Error::InvalidResponse);
            }

            line.push(byte[0]);

            if line.len() > 8192 {
                return Err(Error::InvalidResponse);
            }

            if line.ends_with(b"\r\n") {
                break;
            }
        }

        let line = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| Error::InvalidResponse)?;

        let size_text = line.split(';').next().unwrap_or("");

        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| Error::InvalidResponse)?;

        if size == 0 {
            // Consume trailing headers.
            loop {
                line.clear();

                loop {
                    let mut byte = [0u8; 1];

                    if stream.read(&mut byte)? == 0 {
                        return Err(Error::InvalidResponse);
                    }

                    line.push(byte[0]);

                    if line.ends_with(b"\r\n") {
                        break;
                    }
                }

                if line == b"\r\n" {
                    break;
                }
            }

            return Ok(());
        }

        read_exact_amount(stream, output, size)?;

        let mut crlf = [0u8; 2];

        stream.read_exact(&mut crlf)?;

        if crlf != *b"\r\n" {
            return Err(Error::InvalidResponse);
        }
    }
}

fn read_response(
    stream: &mut Connection,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let headers = read_headers(stream)?;

    let status = parse_status(&headers)?;

    let header_text = std::str::from_utf8(&headers)
        .map_err(|_| Error::InvalidResponse)?;

    let mut parsed_headers = Vec::new();

    for line in header_text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }

        let (name, value) = line
            .split_once(':')
            .ok_or(Error::InvalidHeader)?;

        parsed_headers.push((
            name.to_ascii_lowercase(),
            value.trim().to_string(),
        ));
    }

    let mut body = Vec::new();

    if let Some(value) = header_value(&headers, "transfer-encoding") {
        if value
            .windows(7)
            .any(|w| w.eq_ignore_ascii_case(b"chunked"))
        {
            read_chunked(stream, &mut body)?;
            return Ok((status, parsed_headers, body));
        }
    }

    if let Some(value) = header_value(&headers, "content-length") {
        let length = std::str::from_utf8(value)
            .map_err(|_| Error::InvalidHeader)?
            .trim()
            .parse::<usize>()
            .map_err(|_| Error::InvalidHeader)?;

        read_exact_amount(stream, &mut body, length)?;

        return Ok((status, parsed_headers, body));
    }

    // No Content-Length and no chunked encoding:
    // read until the connection closes.
    let mut buffer = [0u8; 8192];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&buffer[..n]),
            Err(e) => return Err(Error::Io(e)),
        }
    }

    Ok((status, parsed_headers, body))
}

fn header<'a>(
    headers: &'a [(String, String)],
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn get_internal(
    url: &str,
    user_agent: Option<&str>,
    redirects: usize,
) -> Result<Vec<u8>> {
    if redirects > MAX_REDIRECTS {
        return Err(Error::RedirectLimit);
    }

    let parsed = parse_url(url)?;

    let mut stream = connect(&parsed)?;

    let host_header = if parsed.port == 80 && parsed.scheme == "http"
        || parsed.port == 443 && parsed.scheme == "https"
    {
        parsed.host.to_string()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n",
        parsed.path,
        host_header,
        user_agent.unwrap_or("tiny_http_client/0.1"),
    );

    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let (status, headers, body) = read_response(&mut stream)?;

    match status {
        200..=299 => Ok(body),

        301 | 302 | 303 | 307 | 308 => {
            let location = header(&headers, "location")
                .ok_or(Error::InvalidResponse)?;

            get_internal(location, user_agent, redirects + 1)
        }

        _ => Err(Error::HttpStatus(status)),
    }
}

/// Perform an HTTP/HTTPS GET request.
pub fn get(url: &str) -> Result<Vec<u8>> {
    get_internal(url, None, 0)
}

/// Perform an HTTP/HTTPS GET request with a custom User-Agent.
pub fn get_with_user_agent(
    url: &str,
    user_agent: &str,
) -> Result<Vec<u8>> {
    get_internal(url, Some(user_agent), 0)
}
