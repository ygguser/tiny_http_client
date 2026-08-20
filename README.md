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
- Optional built-in CA certificate list
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

By default, the crate uses the system-independent [webpki-roots](https://crates.io/crates/webpki-roots) certificate store on non-Windows platforms.

On Windows, the native Windows certificate store is used.

## CA certificate list

The crate supports an optional `own-cert-list` feature that embeds a selected set of CA root certificates directly into the binary.

This can be useful for small applications that only connect to a known set of HTTPS services and do not need the complete system or `webpki-roots` certificate store.

Enable the feature in `Cargo.toml`:
```toml
[dependencies]
tiny_http_client = {
    git = "https://github.com/ygguser/tiny_http_client",
    features = ["own-cert-list"]
}
```
When `own-cert-list` is enabled:

* only certificates from the crate's `certs/` directory are embedded;
* the certificates are stored in DER format;
* the normal `webpki-roots` certificate list is not used;
* on Windows, the native Windows certificate store is not used;
* the embedded certificates are used as the TLS trust anchors.

The feature is intentionally disabled by default.

### Certificate files

Certificates used by `own-cert-list` are stored in: `certs/*.der`

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
cargo build --release --features own-cert-list
```
### Why use an own certificate list?

Embedding only the root certificates required by an application can reduce the amount of CA data included in the binary and makes the trust store independent of the operating system.

It is especially useful for small standalone utilities that communicate only with a limited number of HTTPS services.

For example, an application that only communicates with GitHub may only need the root CAs required by GitHub and its release/download infrastructure rather than a complete collection of public root certificates.

The application should regenerate the certificate list when the HTTPS services it uses change their certificate chains or when the relevant root certificates change.

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

The client initializes the `ring` crypto provider automatically when the first request is made.

## Default certificate store

By default, trusted root certificates are provided by [webpki-roots]{https://crates.io/crates/webpki-roots} on non-Windows platforms.

On Windows, the native Windows certificate store is used.

## Own certificate list

When the `own-cert-list` feature is enabled, the certificate store is built from the `.der` files in the crate's `certs/` directory.

In this mode, neither `webpki-roots` nor the Windows native certificate store is used.

The TLS connection performs normal server certificate verification against the selected root store.

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

The crate currently does **not** provide:

* asynchronous I/O
* HTTP/2
* HTTP/3
* proxy support
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
