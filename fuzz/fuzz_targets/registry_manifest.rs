#![no_main]

use libfuzzer_sys::fuzz_target;
use nrm_protocol::PROTOCOL_VERSION;
use nrm_registry::parse_manifest;
use semver::Version;

fuzz_target!(|data: &[u8]| {
    let expected_version = Version::new(0, 1, 0);
    let _ = parse_manifest(data, &expected_version, u32::from(PROTOCOL_VERSION));
});
