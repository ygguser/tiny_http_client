# tiny_http_client

A small synchronous HTTP/HTTPS GET/POST client written in Rust.

`tiny_http_client` is designed for small applications and utilities that need basic HTTP/HTTPS functionality without pulling in a full-featured HTTP client stack.

The client uses:

- native Windows / macOS TLS via [`native-tls`](https://crates.io/crates/native-tls);
- optional Linux native TLS via [`native-tls`](https://crates.io/crates/native-tls);
- [`rustls`](https://crates.io/crates/rustls) with [`ring`](https://crates.io/crates/ring) and [`webpki-roots`](https://crates.io/crates/webpki-roots) on Linux;
- Rust's standard networking and I/O APIs.

## Features

The crate provides the following Cargo features:

- `http-get` — enables HTTP GET requests;
- `http-post` — enables HTTP POST requests;
- `linux-native-tls` — enables `native-tls` on Linux and uses the operating system certificate store;
- `linux-own-cert-list` — enables an embedded CA certificate list on Linux.

By default, only `http-get` is enabled.

On Windows and macOS, `native-tls` is always used. On Linux, `rustls` is used by default.

```toml
[features]
default = ["http-get"]
http-get = []
http-post = []
linux-native-tls = ["dep:native-tls"]
linux-own-cert-list = []
```

To enable both GET and POST:

```toml
[dependencies]
tiny_http_client = {
    git = "https://github.com/ygguser/tiny_http_client",
    features = ["http-get", "http-post"]
}
```

If only POST is required:

```toml
[dependencies]
tiny_http_client = {
    git = "https://github.com/ygguser/tiny_http_client",
    default-features = false,
    features = ["http-post"]
}
```

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

## Linux native TLS

On Linux, enable the `linux-native-tls` feature to use `native-tls` and the operating system certificate store:

```toml
[dependencies]
tiny_http_client = {
    git = "https://github.com/ygguser/tiny_http_client",
    default-features = false,
    features = ["http-get", "linux-native-tls"]
}
```

The `linux-native-tls` and `linux-own-cert-list` features are mutually exclusive.

## CA certificate list

The crate supports an optional `linux-own-cert-list` feature that embeds a selected set of CA root certificates directly into the binary.

This can be useful for small applications that only connect to a known set of HTTPS services and do not need the complete system or `webpki-roots` certificate store.

Enable the feature in `Cargo.toml`:
```toml
[dependencies]
tiny_http_client = {
    git = "https://github.com/ygguser/tiny_http_client",
    features = ["linux-own-cert-list"]
}
```
When `linux-own-cert-list` is enabled:

* only certificates from the crate's `certs/` directory are embedded;
* the certificates are stored in DER format;
* the normal `webpki-roots` certificate list is not used;
* on Windows / macOS, the feature has no effect and the native OS certificate store is used;
* on Linux, the embedded certificates are used as the TLS trust anchors.

The feature is intentionally disabled by default.

### Certificate files

Certificates used by `linux-own-cert-list` are stored in: `certs/*.der`

Each file should contain one CA certificate in DER format.

The certificate filenames are not important. The build script automatically finds all `.der` files in the `certs/` directory and generates the Rust source code required to embed them into the binary.

### Generating the certificate list

The repository contains a `get-certs.sh` script for generating a minimal CA certificate list for a specific set of HTTPS hosts.

The hosts are configured near the beginning of the script:
```bash
HOSTS="
github.com
api.github.com
objects.githubusercontent.com
github-releases.githubusercontent.com
"
```
The script:

1. connects to each HTTPS host;
2. obtains the certificates sent by the server;
3. verifies the certificate chain using the system OpenSSL trust store;
4. determines the root CA of the verified chain;
5. extracts the root CA from the system trust store;
6. converts it to DER format;
7. saves it in the `certs/` directory.

For example:
```
certs/
├── ISRG_Root_X1_96bcec06264976f3.der
├── USERTrust_ECC_Certification_Authority_4ff460d54b9c86da.der
└── ...
```
The script does not blindly trust certificates received from the server. Server-provided certificates are used only to determine and verify the certificate chain. The root CA is extracted from the local system trust store.

Run:

```bash
./get-certs.sh
```

The script requires OpenSSL and uses the system CA store to verify the certificate chains.

After updating the certificates, build the application with:
```bash
cargo build --release --features linux-own-cert-list
```
### Why use an own certificate list?

Embedding only the root certificates required by an application can reduce the amount of CA data included in the binary and makes the trust store independent of the operating system.

It is especially useful for small standalone utilities that communicate only with a limited number of HTTPS services.

For example, an application that only communicates with GitHub may only need the root CAs required by GitHub and its release/download infrastructure rather than a complete collection of public root certificates.

The application should regenerate the certificate list when the HTTPS services it uses change their certificate chains or when the relevant root certificates change.

## Basic GET usage

```rust
use tiny_http_client::get;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = get("https://example.com/")?;

    println!("HTTP status: {}", response.status);

    println!("{}", response.as_str()?);

    Ok(())
}
```

## GET request headers

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
Header names and values containing CR or LF characters are rejected to prevent HTTP header injection.

## POST request

POST requests are enabled by the `http-post` feature.

The basic `post()` function sends a request body:

```rust
use tiny_http_client::post;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = post(
        "https://example.com/api",
        b"hello=world",
    )?;

    println!("HTTP status: {}", response.status);

    println!("{}", response.as_str()?);

    Ok(())
}
```

The request body is provided as a byte slice, so binary data can also be sent.

### POST request with headers

Use `post_with_headers()` when custom HTTP headers are required:

```rust
use tiny_http_client::post_with_headers;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_with_headers(
        "https://example.com/api",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("User-Agent", "my-client"),
        ],
        b"hello=world",
    )?;

    println!("HTTP status: {}", response.status);

    println!("{}", response.as_str()?);

    Ok(())
}
```

### JSON POST request

JSON can be sent by providing the appropriate `Content-Type` header:

```rust
use tiny_http_client::post_with_headers;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let body = br#"{"name":"test","value":123}"#;


    let response = post_with_headers(
        "https://example.com/api",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json"),
        ],
        body,
    )?;

    println!("HTTP status: {}", response.status);

    println!("{}", response.as_str()?);

    Ok(())
}
```

The crate does not provide JSON serialization or deserialization. Applications can use any JSON library they prefer, or construct JSON manually when appropriate.

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

## Default certificate store

On Linux, trusted root certificates are provided by [`webpki-roots`](https://crates.io/crates/webpki-roots).

On Windows / macOS, HTTPS connections use the native OS certificate store through [`native-tls`](https://crates.io/crates/native-tls).

## Linux TLS options

On Windows and macOS, HTTPS connections always use `native-tls` and the native operating system certificate store.

On Linux, TLS implementation can be selected using features:

- no Linux TLS feature — `rustls` with Mozilla root certificates from `webpki-roots`;
- `linux-own-cert-list` — `rustls` with CA certificates embedded from the crate's `certs/` directory;
- `linux-native-tls` — `native-tls` with the operating system certificate store.

The `linux-native-tls` and `linux-own-cert-list` features are mutually exclusive.

The TLS connection performs normal server certificate verification against the selected root store.

No client certificates are required.

## Own certificate list

On Linux, when the `linux-own-cert-list` feature is enabled, the certificate store is built from the `.der` files in the crate's `certs/` directory.

In this mode, `webpki-roots` is not used. The embedded certificates are used as the TLS trust anchors.

## Redirects

Supported HTTP redirects:

* 301 Moved Permanently
* 302 Found
* 303 See Other
* 307 Temporary Redirect
* 308 Permanent Redirect

Up to 5 redirects are followed automatically.

```rust
const MAX_REDIRECTS: usize = 5;
```

## Timeouts

The connection timeout is:
```rust
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
```
The same timeout is also applied to socket reads and writes.

## Design goals

The main goal of this crate is to provide a small dependency footprint and a simple API for applications that only need basic synchronous HTTP/HTTPS GET and POST requests.

The crate intentionally uses platform-specific TLS implementations:

* native TLS on Windows;
* native TLS on macOS;
* rustls on Linux.

This keeps each platform's implementation simple and lets Windows and macOS use their native TLS implementations and certificate stores.

It intentionally does not attempt to implement a complete HTTP client.

The crate currently does **not** provide:

* asynchronous I/O
* HTTP/2
* HTTP/3
* proxy support
* cookies
* connection pooling
* multipart requests
* PUT/PATCH/DELETE helpers
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

Responses with a status code outside the 200..=299 range are returned as errors.

## License

MIT License.

Copyright (C) ygguser 2026.

See [LICENSE](LICENSE) for the full license text.
