#![no_main]

use libfuzzer_sys::fuzz_target;
use nrm_registry::parse_signature_document;

fuzz_target!(|data: &[u8]| {
    let _ = parse_signature_document(data);
});
