use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use semver::Version;
use thiserror::Error;
use url::{Host, Url};

const VERSION_PLACEHOLDER: &str = "{version}";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryUrlTemplate {
    template: String,
}

impl RegistryUrlTemplate {
    pub fn parse(template: &str) -> Result<Self, UrlPolicyError> {
        if template.matches(VERSION_PLACEHOLDER).count() != 1 {
            return Err(UrlPolicyError::VersionPlaceholderCount);
        }
        let without_placeholder = template.replacen(VERSION_PLACEHOLDER, "", 1);
        if without_placeholder.contains(['{', '}']) {
            return Err(UrlPolicyError::UnexpectedPlaceholder);
        }
        let probe = template.replace(VERSION_PLACEHOLDER, "0.0.0");
        if raw_authority_contains_at(&probe) {
            return Err(UrlPolicyError::Credentials);
        }
        let parsed = Url::parse(&probe).map_err(UrlPolicyError::InvalidUrl)?;
        if parsed.scheme() == "file" && !probe.starts_with("file://") {
            return Err(UrlPolicyError::FileUrlNotLocalAbsolute);
        }
        validate_manifest_url(&parsed)?;
        Ok(Self {
            template: template.to_owned(),
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.template
    }

    pub fn expand(&self, version: &Version) -> Result<Url, UrlPolicyError> {
        let expanded = self
            .template
            .replace(VERSION_PLACEHOLDER, &version.to_string());
        let url = Url::parse(&expanded).map_err(UrlPolicyError::InvalidUrl)?;
        validate_manifest_url(&url)?;
        Ok(url)
    }
}

#[derive(Debug, Error)]
pub enum UrlPolicyError {
    #[error("registry URL must contain exactly one literal {{version}} placeholder")]
    VersionPlaceholderCount,
    #[error("registry URL contains an unsupported placeholder or unmatched brace")]
    UnexpectedPlaceholder,
    #[error("registry URL is invalid: {0}")]
    InvalidUrl(url::ParseError),
    #[error("registry URL scheme must be https or file, not {0:?}")]
    UnsupportedScheme(String),
    #[error("registry URLs must not contain credentials")]
    Credentials,
    #[error("registry URLs must not contain a query string or fragment")]
    QueryOrFragment,
    #[error("HTTPS registry URL must have a host")]
    MissingHost,
    #[error("HTTPS registry URL uses localhost or a non-global literal host")]
    LocalOrPrivateHost,
    #[error("file registry URL must be local and absolute")]
    FileUrlNotLocalAbsolute,
    #[error("manifest URL must name a file")]
    MissingManifestFilename,
    #[error("artifact filename is not a safe single path component: {0:?}")]
    InvalidArtifactFilename(String),
}

pub fn validate_https_url(url: &Url) -> Result<(), UrlPolicyError> {
    if url.scheme() != "https" {
        return Err(UrlPolicyError::UnsupportedScheme(url.scheme().to_owned()));
    }
    validate_common(url)?;
    let host = url.host().ok_or(UrlPolicyError::MissingHost)?;
    if !host_is_globally_routable(host) {
        return Err(UrlPolicyError::LocalOrPrivateHost);
    }
    Ok(())
}

pub(crate) fn host_is_globally_routable(host: Host<&str>) -> bool {
    match host {
        Host::Ipv4(address) => ipv4_is_globally_routable(address),
        Host::Ipv6(address) => ipv6_is_globally_routable(address),
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            domain != "localhost" && !domain.ends_with(".localhost")
        }
    }
}

pub fn signature_url(manifest_url: &Url) -> Result<Url, UrlPolicyError> {
    validate_manifest_url(manifest_url)?;
    let signature = Url::parse(&format!("{}.sig", manifest_url.as_str()))
        .map_err(UrlPolicyError::InvalidUrl)?;
    validate_manifest_url(&signature)?;
    Ok(signature)
}

pub fn artifact_url(manifest_url: &Url, filename: &str) -> Result<Url, UrlPolicyError> {
    validate_manifest_url(manifest_url)?;
    validate_artifact_filename(filename)?;
    sibling_url(manifest_url, filename)
}

pub fn validate_artifact_filename(filename: &str) -> Result<(), UrlPolicyError> {
    if filename.is_empty()
        || filename == "."
        || filename == ".."
        || filename.len() > 255
        || filename
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\' | b':' | b'%' | 0))
        || Path::new(filename).components().count() != 1
    {
        return Err(UrlPolicyError::InvalidArtifactFilename(filename.to_owned()));
    }
    Ok(())
}

fn validate_manifest_url(url: &Url) -> Result<(), UrlPolicyError> {
    match url.scheme() {
        "https" => validate_https_url(url)?,
        "file" => {
            validate_common(url)?;
            if url.host().is_some()
                || url
                    .to_file_path()
                    .ok()
                    .is_none_or(|path| !path.is_absolute())
            {
                return Err(UrlPolicyError::FileUrlNotLocalAbsolute);
            }
        }
        scheme => return Err(UrlPolicyError::UnsupportedScheme(scheme.to_owned())),
    }
    manifest_filename(url)?;
    Ok(())
}

fn validate_common(url: &Url) -> Result<(), UrlPolicyError> {
    if !url.username().is_empty() || url.password().is_some() || authority_contains_at(url) {
        return Err(UrlPolicyError::Credentials);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(UrlPolicyError::QueryOrFragment);
    }
    Ok(())
}

fn authority_contains_at(url: &Url) -> bool {
    raw_authority_contains_at(url.as_str())
}

fn raw_authority_contains_at(value: &str) -> bool {
    let Some(after_scheme) = value.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

fn manifest_filename(url: &Url) -> Result<&str, UrlPolicyError> {
    url.path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
        .ok_or(UrlPolicyError::MissingManifestFilename)
}

fn sibling_url(url: &Url, filename: &str) -> Result<Url, UrlPolicyError> {
    let mut sibling = url.clone();
    {
        let mut segments = sibling
            .path_segments_mut()
            .map_err(|()| UrlPolicyError::MissingManifestFilename)?;
        segments.pop();
        segments.push(filename);
    }
    validate_manifest_url(&sibling)?;
    Ok(sibling)
}

fn ipv4_is_globally_routable(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn ipv6_is_globally_routable(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let embeds_ipv4 = segments[..6].iter().all(|segment| *segment == 0)
        || (segments[..5].iter().all(|segment| *segment == 0) && segments[5] == 0xffff);
    let global_unicast = segments[0] & 0xe000 == 0x2000;
    let special_purpose = (segments[0] == 0x2001
        && matches!(segments[1], 0x0000 | 0x0002 | 0x0010..=0x002f | 0x0db8))
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && segments[1] <= 0x0fff);
    global_unicast && !special_purpose && !embeds_ipv4
}
