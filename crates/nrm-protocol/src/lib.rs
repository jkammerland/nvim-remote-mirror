use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

pub type RequestId = u64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilitySet {
    pub scan: bool,
    pub read: bool,
    pub write_cas: bool,
    pub checksum: bool,
    pub grep: bool,
    pub lsp_proxy: bool,
    pub batch_read: bool,
    pub batch_validate: bool,
    pub request_ids: bool,
    pub cancellation: bool,
    pub streaming: bool,
    pub multiplexing: bool,
}

impl CapabilitySet {
    pub fn v1_agent() -> Self {
        Self {
            scan: true,
            read: true,
            write_cas: true,
            checksum: true,
            grep: true,
            lsp_proxy: false,
            batch_read: true,
            batch_validate: true,
            request_ids: true,
            cancellation: false,
            streaming: false,
            multiplexing: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMeta {
    pub path: String,
    pub size: u64,
    pub mtime_ms: i64,
    pub mode: u32,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchHit {
    pub path: String,
    pub line: u64,
    pub column: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchReadFile {
    pub path: String,
    pub content: Vec<u8>,
    pub hash: String,
    pub meta: FileMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchReadError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchValidateFile {
    pub path: String,
    pub meta: Option<FileMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SaveApplied {
    pub path: String,
    pub new_hash: String,
    pub size: u64,
    pub mtime_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SaveConflict {
    pub path: String,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub remote_content: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SaveOutcome {
    Applied(SaveApplied),
    Conflict(SaveConflict),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Request {
    Hello {
        client_version: String,
        protocol_version: u16,
    },
    Scan {
        limit: usize,
    },
    Stat {
        path: String,
    },
    Checksum {
        path: String,
    },
    ValidateFiles {
        paths: Vec<String>,
        include_hash: bool,
    },
    ReadFile {
        path: String,
        offset: u64,
        len: Option<u64>,
    },
    ReadFiles {
        paths: Vec<String>,
        max_file_bytes: u64,
        max_total_bytes: u64,
    },
    Grep {
        query: String,
        limit: usize,
    },
    WriteFileCas {
        path: String,
        expected_hash: Option<String>,
        content: Vec<u8>,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Response {
    Hello {
        agent_version: String,
        protocol_version: u16,
        capabilities: CapabilitySet,
    },
    Scan {
        entries: Vec<FileMeta>,
        truncated: bool,
    },
    Stat {
        meta: Option<FileMeta>,
    },
    Checksum {
        path: String,
        hash: Option<String>,
    },
    ValidateFiles {
        files: Vec<BatchValidateFile>,
        errors: Vec<BatchReadError>,
    },
    ReadFile {
        path: String,
        offset: u64,
        eof: bool,
        content: Vec<u8>,
        hash: String,
        meta: FileMeta,
    },
    ReadFiles {
        files: Vec<BatchReadFile>,
        errors: Vec<BatchReadError>,
        truncated: bool,
    },
    Grep {
        hits: Vec<SearchHit>,
        truncated: bool,
    },
    WriteFileCas {
        outcome: SaveOutcome,
    },
    Ack,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RpcErrorCode {
    Agent,
    Protocol,
    Cancelled,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcError {
    pub code: RpcErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl RpcError {
    pub fn agent(message: impl Into<String>) -> Self {
        Self {
            code: RpcErrorCode::Agent,
            message: message.into(),
            retryable: false,
        }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self {
            code: RpcErrorCode::Protocol,
            message: message.into(),
            retryable: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RpcMessage {
    Request { id: RequestId, request: Request },
    Response { id: RequestId, response: Response },
    Error { id: RequestId, error: RpcError },
    Cancel { id: RequestId },
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame length {0} exceeds maximum {MAX_FRAME_LEN}")]
    TooLarge(usize),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec error: {0}")]
    Codec(#[from] Box<bincode::ErrorKind>),
}

pub fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: Write,
    T: Serialize,
{
    let bytes = bincode::serialize(value)?;
    if bytes.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(bytes.len()));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: Read,
    for<'de> T: Deserialize<'de>,
{
    let mut len_buf = [0_u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bincode::deserialize(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trips_request_frame() {
        let request = RpcMessage::Request {
            id: 42,
            request: Request::ReadFile {
                path: "src/main.rs".to_string(),
                offset: 10,
                len: Some(512),
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn round_trips_typed_rpc_error() {
        let message = RpcMessage::Error {
            id: 7,
            error: RpcError {
                code: RpcErrorCode::Protocol,
                message: "bad frame".to_string(),
                retryable: false,
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &message).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn round_trips_batch_read_request() {
        let request = RpcMessage::Request {
            id: 8,
            request: Request::ReadFiles {
                paths: vec!["a.txt".to_string(), "src/lib.rs".to_string()],
                max_file_bytes: 1024,
                max_total_bytes: 4096,
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn round_trips_batch_validate_request() {
        let request = RpcMessage::Request {
            id: 9,
            request: Request::ValidateFiles {
                paths: vec!["a.txt".to_string(), "deleted.txt".to_string()],
                include_hash: true,
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn rejects_oversized_frame_before_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes());
        let result: Result<Request, FrameError> = read_frame(&mut Cursor::new(bytes));
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
    }
}
