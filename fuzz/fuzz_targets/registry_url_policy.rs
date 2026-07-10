#![no_main]

use libfuzzer_sys::fuzz_target;
use nrm_registry::{
    artifact_url, signature_url, validate_https_url, validate_redirect_url, RegistryUrlTemplate,
};
use semver::Version;
use url::Url;

fuzz_target!(|data: &[u8]| {
    let split = data
        .iter()
        .position(|byte| matches!(*byte, 0 | b'\n'))
        .unwrap_or(data.len());
    let (url_bytes, filename_bytes) = data.split_at(split);
    let mut filename_bytes = filename_bytes.get(1..).unwrap_or_default();
    if let Some(without_newline) = filename_bytes.strip_suffix(b"\n") {
        filename_bytes = without_newline;
    }
    if let Some(without_carriage_return) = filename_bytes.strip_suffix(b"\r") {
        filename_bytes = without_carriage_return;
    }

    if let Ok(input) = std::str::from_utf8(url_bytes) {
        if let Ok(template) = RegistryUrlTemplate::parse(input) {
            if let Ok(manifest_url) = template.expand(&Version::new(0, 1, 0)) {
                let _ = signature_url(&manifest_url);
                let _ = validate_https_url(&manifest_url);
                if let Ok(filename) = std::str::from_utf8(filename_bytes) {
                    let _ = artifact_url(&manifest_url, filename);
                }
            }
        }

        if let Ok(url) = Url::parse(input) {
            let _ = validate_https_url(&url);
            if let Ok(signature) = signature_url(&url) {
                assert_eq!(signature.as_str(), format!("{}.sig", url.as_str()));
            }
            if let Ok(filename) = std::str::from_utf8(filename_bytes) {
                let _ = artifact_url(&url, filename);
                if let Ok(redirect) = validate_redirect_url(&url, filename) {
                    assert_eq!(redirect.scheme(), "https");
                    assert!(redirect.username().is_empty());
                    assert!(redirect.password().is_none());
                    assert!(redirect.fragment().is_none());
                }
            }
        }
    }
});
