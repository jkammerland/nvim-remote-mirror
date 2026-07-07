#![no_main]

use libfuzzer_sys::fuzz_target;
use nrm_protocol::{read_frame, write_frame, FrameError, RpcMessage, MAX_FRAME_LEN};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    match read_frame::<_, RpcMessage>(&mut cursor) {
        Ok(message) => {
            let mut encoded = Vec::new();
            if write_frame(&mut encoded, &message).is_ok() {
                let mut encoded_cursor = Cursor::new(encoded);
                let decoded: RpcMessage = read_frame(&mut encoded_cursor)
                    .expect("encoded protocol message should decode");
                assert_eq!(decoded, message);
            }
        }
        Err(FrameError::TooLarge(len)) => {
            assert!(len > MAX_FRAME_LEN);
        }
        Err(FrameError::Io(_) | FrameError::Codec(_)) => {}
    }
});
