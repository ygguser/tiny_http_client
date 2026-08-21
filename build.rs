use std::env;
use std::fs;
use std::path::PathBuf;

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
            "linux-own-cert-list is enabled, but no *.der certificates were found in {}",
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

    #[cfg(target_os = "linux")]
    {
        let linux_own_cert_list = env::var_os("CARGO_FEATURE_LINUX_OWN_CERT_LIST").is_some();
        let linux_native_tls = env::var_os("CARGO_FEATURE_LINUX_NATIVE_TLS").is_some();

        if linux_own_cert_list && linux_native_tls {
            panic!(
                "features `linux-native-tls` and `linux-own-cert-list` cannot be enabled at the same time"
            );
        }

        if linux_own_cert_list {
            build_own_cert_list();
        }
    }
}
