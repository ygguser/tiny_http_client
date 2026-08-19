# tiny_http_client

A small synchronous HTTP/HTTPS GET client written in Rust.

`tiny_http_client` is designed for small applications and utilities that need
basic HTTP/HTTPS functionality without pulling in a full-featured HTTP client
stack.

The client uses:

- [`rustls`](https://crates.io/crates/rustls) for TLS
- [`ring`](https://crates.io/crates/ring) as the TLS cryptographic provider
- [`webpki-roots`](https://crates.io/crates/webpki-roots) for trusted CA roots
- Rust's standard networking and I/O APIs

## Features

- HTTP GET
- HTTPS GET
- TLS certificate verification
- HTTP request headers
- HTTP response headers
- HTTP status codes
- HTTP redirects
- Relative and absolute redirect URLs
- Protocol-relative redirects
- `Transfer-Encoding: chunked`
- IPv4 and IPv6 addresses
- Connection and I/O timeouts
- No asynchronous runtime
- Small and simple API

Supported HTTP redirects:

- `301 Moved Permanently`
- `302 Found`
- `303 See Other`
- `307 Temporary Redirect`
- `308 Permanent Redirect`

Up to 5 redirects are followed automatically.

## Installation

Add the following dependency to `Cargo.toml`:

```toml
[dependencies]
tiny_http_client = { git = "https://github.com/ygguser/tiny_http_client" }
```
Or use a specific revision:

```toml
[dependencies]
tiny_http_client = { git = "https://github.com/ygguser/tiny_http_client", rev = "26f03556e38417c1366ab86e08daeaebd95c7604" }
```

## Basic usage

```rust
use tiny_http_client::get;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = get("https://example.com/")?;

    println!("HTTP status: {}", response.status);

    println!("{}", response.as_str()?);

    Ok(())
}
```

## Request headers

Use `get_with_headers()` when custom HTTP headers are required:

```rust
use tiny_http_client::get_with_headers;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = get_with_headers(
        "https://api.github.com/repos/ygguser/peers_updater/releases/latest",
        &[
            ("User-Agent", "peers_updater"),
            ("Accept", "application/json"),
        ],
    )?;

    println!("HTTP status: {}", response.status);

    println!("{}", response.as_str()?);

    Ok(())
}
```
Header names and values containing CR or LF characters are rejected to prevent
HTTP header injection.

## Response

The `Response` structure contains:
```rust
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
```

## Status code

```rust
println!("{}", response.status);
```

## Response body as bytes

```rust
let data: &[u8] = response.as_bytes();
```
## Response body as UTF-8

```rust
let text = response.as_str()?;
println!("{}", text);
```
## Response headers

Use `header()` to retrieve a header without worrying about capitalization:

```rust
if let Some(content_type) = response.header("Content-Type") {
    println!("Content-Type: {}", content_type);
}
```

## HTTPS and TLS

HTTPS connections are implemented using `rustls`.

The client initializes the `ring` crypto provider automatically when the first
request is made.

The trusted root certificates are provided by `webpki-roots`.

The TLS connection performs normal server certificate verification based on the
trusted root store.

No client certificates are required.

## Redirects

Redirects are followed automatically.

## Timeouts

The connection timeout is:
```rust
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
```
The same timeout is also applied to socket reads and writes.

## Design goals

The main goal of this crate is to provide a small dependency footprint and a
simple API for applications that only need basic synchronous HTTP/HTTPS GET
requests.

It intentionally does not attempt to implement a complete HTTP client.

The crate currently does not provide:

* asynchronous I/O
* HTTP/2
* HTTP/3
*proxy support
* cookies
* connection pooling
* multipart requests
* POST/PUT/PATCH/DELETE helpers
* automatic content compression
* automatic decompression
* authentication helpers

These features can be implemented by the application when needed.

## Error handling

All public request functions return:
```rust
Result<Response, Box<dyn std::error::Error>>
```
Examples of errors include:

* unsupported URL scheme
* DNS resolution failure
* TCP connection failure
* connection timeout
* TLS errors
* invalid HTTP responses
* invalid HTTP headers
* invalid chunked encoding
* too many redirects
* non-2xx HTTP status codes

For example:
```rust
match tiny_http_client::get("https://example.com/") {
    Ok(response) => {
        println!("Status: {}", response.status);
    }


    Err(error) => {
        eprintln!("HTTP request failed: {}", error);
    }
}
```

## Non-2xx responses

Responses with a status code outside the 200..=299 range are returned as
errors.

## License

MIT License.

Copyright (C) ygguser 2026.

See [LICENSE](LICENSE) for the full license text.
