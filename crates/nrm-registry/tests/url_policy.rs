use nrm_registry::{
    artifact_url, signature_url, validate_artifact_filename, validate_https_url,
    RegistryUrlTemplate, UrlPolicyError,
};
use semver::Version;
use url::Url;

fn version() -> Version {
    Version::parse("1.2.3").unwrap()
}

#[test]
fn parses_and_expands_https_and_absolute_file_templates() {
    let https = RegistryUrlTemplate::parse(
        "https://releases.example/nrm/v{version}/nrm-agent-manifest-v1.json",
    )
    .unwrap();
    assert_eq!(
        https.expand(&version()).unwrap().as_str(),
        "https://releases.example/nrm/v1.2.3/nrm-agent-manifest-v1.json"
    );

    let file =
        RegistryUrlTemplate::parse("file:///var/lib/nrm/v{version}/nrm-agent-manifest-v1.json")
            .unwrap();
    assert_eq!(
        file.expand(&version()).unwrap().as_str(),
        "file:///var/lib/nrm/v1.2.3/nrm-agent-manifest-v1.json"
    );
}

#[test]
fn requires_exactly_one_literal_version_placeholder() {
    for template in [
        "https://example.test/manifest.json",
        "https://example.test/{version}/{version}/manifest.json",
        "https://example.test/%7Bversion%7D/manifest.json",
    ] {
        assert!(matches!(
            RegistryUrlTemplate::parse(template),
            Err(UrlPolicyError::VersionPlaceholderCount)
        ));
    }

    for template in [
        "https://example.test/{version}/{other}/manifest.json",
        "https://example.test/{version}/manifest-{.json",
        "https://example.test/{version}/manifest}.json",
    ] {
        assert!(matches!(
            RegistryUrlTemplate::parse(template),
            Err(UrlPolicyError::UnexpectedPlaceholder)
        ));
    }
}

#[test]
fn rejects_unsupported_relative_or_nonlocal_urls() {
    for template in [
        "http://example.test/v{version}/manifest.json",
        "ftp://example.test/v{version}/manifest.json",
        "/tmp/v{version}/manifest.json",
    ] {
        assert!(RegistryUrlTemplate::parse(template).is_err(), "{template}");
    }

    assert!(matches!(
        RegistryUrlTemplate::parse("file://server/share/v{version}/manifest.json"),
        Err(UrlPolicyError::FileUrlNotLocalAbsolute)
    ));
    assert!(matches!(
        RegistryUrlTemplate::parse("file:relative/v{version}/manifest.json"),
        Err(UrlPolicyError::FileUrlNotLocalAbsolute)
    ));
}

#[test]
fn rejects_credentials_queries_fragments_and_missing_filenames() {
    for template in [
        "https://user@example.test/v{version}/manifest.json",
        "https://:password@example.test/v{version}/manifest.json",
        "https://@example.test/v{version}/manifest.json",
    ] {
        assert!(matches!(
            RegistryUrlTemplate::parse(template),
            Err(UrlPolicyError::Credentials)
        ));
    }

    for template in [
        "https://example.test/v{version}/manifest.json?token=secret",
        "https://example.test/v{version}/manifest.json?",
        "https://example.test/v{version}/manifest.json#fragment",
    ] {
        assert!(matches!(
            RegistryUrlTemplate::parse(template),
            Err(UrlPolicyError::QueryOrFragment)
        ));
    }

    assert!(matches!(
        RegistryUrlTemplate::parse("https://example.test/v{version}/"),
        Err(UrlPolicyError::MissingManifestFilename)
    ));
}

#[test]
fn rejects_private_loopback_link_local_and_unspecified_literal_hosts() {
    for url in [
        "https://127.0.0.1/manifest.json",
        "https://127.1/manifest.json",
        "https://2130706433/manifest.json",
        "https://0177.0.0.1/manifest.json",
        "https://10.0.0.1/manifest.json",
        "https://172.16.1.2/manifest.json",
        "https://192.168.1.2/manifest.json",
        "https://169.254.1.2/manifest.json",
        "https://0.0.0.0/manifest.json",
        "https://[::1]/manifest.json",
        "https://[::]/manifest.json",
        "https://[fc00::1]/manifest.json",
        "https://[fe80::1]/manifest.json",
        "https://[::ffff:127.0.0.1]/manifest.json",
        "https://localhost/manifest.json",
        "https://localhost./manifest.json",
        "https://registry.localhost/manifest.json",
        "https://registry.localhost./manifest.json",
        "https://100.64.0.1/manifest.json",
        "https://192.0.2.1/manifest.json",
        "https://224.0.0.1/manifest.json",
        "https://240.0.0.1/manifest.json",
        "https://[ff02::1]/manifest.json",
        "https://[2001:db8::1]/manifest.json",
        "https://[::192.0.2.1]/manifest.json",
    ] {
        assert!(
            matches!(
                validate_https_url(&Url::parse(url).unwrap()),
                Err(UrlPolicyError::LocalOrPrivateHost)
            ),
            "{url}"
        );
    }

    validate_https_url(&Url::parse("https://8.8.8.8/manifest.json").unwrap()).unwrap();
    validate_https_url(&Url::parse("https://[2606:4700:4700::1111]/manifest.json").unwrap())
        .unwrap();
}

#[test]
fn resolves_signature_and_artifact_beside_manifest() {
    let manifest =
        Url::parse("https://example.test/releases/v1.2.3/nrm-agent-manifest-v1.json").unwrap();
    assert_eq!(
        signature_url(&manifest).unwrap().as_str(),
        "https://example.test/releases/v1.2.3/nrm-agent-manifest-v1.json.sig"
    );
    assert_eq!(
        artifact_url(&manifest, "nrm-agent-1.2.3-aarch64-apple-darwin")
            .unwrap()
            .as_str(),
        "https://example.test/releases/v1.2.3/nrm-agent-1.2.3-aarch64-apple-darwin"
    );

    let encoded = Url::parse("https://example.test/a%20b/manifest%20v1.json").unwrap();
    assert_eq!(
        signature_url(&encoded).unwrap().as_str(),
        "https://example.test/a%20b/manifest%20v1.json.sig"
    );

    let file = Url::parse("file:///tmp/registry/v1/manifest.json").unwrap();
    assert_eq!(
        artifact_url(&file, "nrm-agent-1.2.3-x86_64-pc-windows-msvc.exe")
            .unwrap()
            .as_str(),
        "file:///tmp/registry/v1/nrm-agent-1.2.3-x86_64-pc-windows-msvc.exe"
    );
}

#[test]
fn artifact_names_are_single_safe_literal_components() {
    validate_artifact_filename("nrm-agent-1.2.3-aarch64-apple-darwin").unwrap();
    validate_artifact_filename("nrm-agent-1.2.3-x86_64-pc-windows-msvc.exe").unwrap();

    for filename in [
        "",
        ".",
        "..",
        "../agent",
        "dir/agent",
        "dir\\agent",
        "B:agent",
        "%2e%2e",
        "agent\0",
        "agent\n",
    ] {
        assert!(
            matches!(
                validate_artifact_filename(filename),
                Err(UrlPolicyError::InvalidArtifactFilename(_))
            ),
            "{filename:?}"
        );
    }
}
