use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{
    ClientConfig,
    ClientConnection,
    RootCertStore,
    StreamOwned,
};

use webpki_roots::TLS_SERVER_ROOTS;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn get(url: &str) -> Result<Response> {
    request("GET", url, &[])
}

pub fn get_with_headers(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Response> {
    request("GET", url, headers)
}

fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Response> {
    let url = parse_url(url)?;

    let tcp = TcpStream::connect((url.host.as_str(), url.port))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let mut roots = RootCertStore::empty();

    roots.extend(TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let config = Arc::new(config);

    let server_name = url.host.as_str().try_into()?;

    let connection = ClientConnection::new(config, server_name)?;

    let mut stream = StreamOwned::new(connection, tcp);

    write!(
        stream,
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: peers_updater\r\n\
         Connection: close\r\n",
        method,
        url.path,
        url.host
    )?;

    for &(name, value) in headers {
        write!(stream, "{}: {}\r\n", name, value)?;
    }

    write!(stream, "\r\n")?;
    stream.flush()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    parse_response(&response)
}


struct Url {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<Url> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("only https:// URLs are supported")?;

    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.rfind(':') {
        Some(pos) if host_port[pos + 1..].parse::<u16>().is_ok() => {
            (
                &host_port[..pos],
                host_port[pos + 1..].parse::<u16>()?,
            )
        }
        _ => (host_port, 443),
    };

    if host.is_empty() {
        return Err("empty hostname".into());
    }

    Ok(Url {
        host: host.to_owned(),
        port,
        path: path.to_owned(),
    })
}


fn parse_response(data: &[u8]) -> Result<Response> {
    let header_end = find_bytes(data, b"\r\n\r\n")
        .ok_or("invalid HTTP response")?;

    let headers = &data[..header_end];
    let body_start = header_end + 4;

    let first_line_end = find_bytes(headers, b"\r\n")
        .ok_or("invalid HTTP response")?;

    let status_line = std::str::from_utf8(&headers[..first_line_end])?;

    let mut parts = status_line.split_whitespace();

    let _http_version = parts.next().ok_or("invalid HTTP status line")?;

    let status = parts
        .next()
        .ok_or("missing HTTP status")?
        .parse::<u16>()?;

    let body = &data[body_start..];

    Ok(Response {
        status,
        body: body.to_vec(),
    })
}


fn find_bytes(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() {
        return Some(0);
    }

    if data.len() < pattern.len() {
        return None;
    }

    for i in 0..=data.len() - pattern.len() {
        if &data[i..i + pattern.len()] == pattern {
            return Some(i);
        }
    }

    None
}
