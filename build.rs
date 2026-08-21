use std::env;
use std::fs;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
fn build_macos_network_tls() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is not set"),
    );

    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR")
            .expect("OUT_DIR is not set"),
    );

    let target = env::var("TARGET")
        .expect("TARGET is not set");

    let source = manifest_dir.join("macos/network_tls.c");
    let object = out_dir.join("network_tls.o");
    let library = out_dir.join("libtiny_network_tls.a");

    /*
     * Rust targets:
     *
     *   x86_64-apple-darwin
     *   aarch64-apple-darwin
     *
     * clang understands these target triples directly.
     */
    let clang_target = match target.as_str() {
        "x86_64-apple-darwin" => "x86_64-apple-darwin",
        "aarch64-apple-darwin" => "aarch64-apple-darwin",
        _ => panic!("unsupported macOS target: {}", target),
    };

    // Compile C source into an object file for the same architecture
    // as the Rust target.
    let status = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "clang",
            "-target",
            clang_target,
            "-fblocks",
            "-c",
        ])
        .arg(&source)
        .args(["-o"])
        .arg(&object)
        .status()
        .expect("failed to execute xcrun clang");

    if !status.success() {
        panic!("failed to compile macOS Network.framework TLS shim");
    }

    // Create a static library containing the object file.
    let status = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "ar",
            "rcs",
        ])
        .arg(&library)
        .arg(&object)
        .status()
        .expect("failed to execute xcrun ar");

    if !status.success() {
        panic!("failed to create macOS Network.framework TLS library");
    }

    // Tell Cargo where the static library is located.
    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.display()
    );

    // Link our static library.
    println!("cargo:rustc-link-lib=static=tiny_network_tls");

    // Link Apple's Network.framework.
    println!("cargo:rustc-link-lib=framework=Network");

    // Re-run build.rs when the C source changes.
    println!(
        "cargo:rerun-if-changed={}",
        source.display()
    );
}

fn build_own_cert_list() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let certs_dir = manifest_dir.join("certs");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let output = out_dir.join("own_certs.rs");

    let mut entries = Vec::new();

    let dir = match fs::read_dir(&certs_dir) {
        Ok(dir) => dir,
        Err(error) => {
            panic!(
                "failed to read certificate directory {}: {}",
                certs_dir.display(),
                error
            );
        }
    };

    for entry in dir {
        let entry = entry.expect("failed to read certificate directory entry");
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("der") {
            continue;
        }

        let path_str = path.to_str().expect("certificate path is not valid UTF-8");
        entries.push(path_str.to_owned());
    }

    entries.sort();

    if entries.is_empty() {
        panic!(
            "own-cert-list is enabled, but no *.der certificates were found in {}",
            certs_dir.display()
        );
    }

    let mut code = String::new();
    code.push_str("use rustls::pki_types::CertificateDer;\n\n");
    code.push_str("pub fn load() -> Vec<CertificateDer<'static>> {\n");
    code.push_str("    vec![\n");

    for path in entries {
        code.push_str(&format!(
            "        CertificateDer::from(include_bytes!({path:?}).to_vec()),\n",
        ));
    }

    code.push_str("    ]\n");
    code.push_str("}\n");

    fs::write(&output, code).expect("failed to write generated certificate list");

    println!(
        "cargo:rustc-env=TINY_HTTP_CLIENT_OWN_CERTS={}",
        output.display()
    );
}

fn main() {
    println!("cargo:rerun-if-changed=certs");

    #[cfg(target_os = "macos")]
    {
        build_macos_network_tls();
    }

    if env::var_os("CARGO_FEATURE_OWN_CERT_LIST").is_some() && cfg!(target_os = "linux") {
        build_own_cert_list();
    }
}
