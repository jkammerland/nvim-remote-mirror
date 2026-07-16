#![no_main]

use libfuzzer_sys::fuzz_target;
use nrm_protocol::{
    read_runtime_frame, write_runtime_frame, RuntimeFrameError, RuntimeMessage,
    RUNTIME_MAX_FRAME_LEN,
};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    match read_runtime_frame(&mut cursor) {
        Ok(message) => {
            let mut encoded = Vec::new();
            if write_runtime_frame(&mut encoded, &message).is_ok() {
                let mut encoded_cursor = Cursor::new(encoded);
                let decoded: RuntimeMessage = read_runtime_frame(&mut encoded_cursor)
                    .expect("encoded runtime message should decode");
                assert_eq!(decoded, message);
            }
        }
        Err(RuntimeFrameError::TooLarge(len)) => {
            assert!(len > RUNTIME_MAX_FRAME_LEN);
        }
        Err(
            RuntimeFrameError::Io(_)
            | RuntimeFrameError::Codec(_)
            | RuntimeFrameError::Invalid(_),
        ) => {}
    }
});
