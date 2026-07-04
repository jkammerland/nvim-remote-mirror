#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const PROTOCOL_VERSION: u16 = 6;
pub const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;
pub const MAX_CONFLICT_CONTENT_BYTES: usize = 4 * 1024 * 1024;

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
    pub chunked_write: bool,
    pub request_ids: bool,
    pub cancellation: bool,
    pub streaming: bool,
    pub multiplexing: bool,
    pub git: bool,
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
            chunked_write: true,
            request_ids: true,
            cancellation: false,
            streaming: false,
            multiplexing: false,
            git: true,
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
pub struct GitCommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub status_code: Option<i32>,
    pub truncated: bool,
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
    pub remote_content_truncated: bool,
    pub remote_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SaveOutcome {
    Applied(SaveApplied),
    Conflict(SaveConflict),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteStarted {
    pub upload_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WriteStartOutcome {
    Started(WriteStarted),
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
        after: Option<String>,
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
        after: Option<String>,
        max_files: Option<usize>,
        max_file_bytes: Option<u64>,
        max_total_bytes: Option<u64>,
        session_id: Option<String>,
    },
    GitStatus {
        paths: Vec<String>,
        max_output_bytes: u64,
    },
    GitDiff {
        path: Option<String>,
        cached: bool,
        max_output_bytes: u64,
    },
    GitBlame {
        path: String,
        max_output_bytes: u64,
    },
    WriteFileCas {
        path: String,
        expected_hash: Option<String>,
        content: Vec<u8>,
    },
    BeginWriteFileCas {
        path: String,
        expected_hash: Option<String>,
        content_hash: String,
        size: u64,
    },
    WriteFileChunk {
        upload_id: String,
        offset: u64,
        content: Vec<u8>,
    },
    FinishWriteFileCas {
        upload_id: String,
    },
    AbortWriteFileCas {
        upload_id: String,
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
        /// Full-file content hash. This is populated on the EOF chunk and left
        /// empty on non-EOF chunks so large reads do not rehash the same remote
        /// file once per chunk.
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
        next_after: Option<String>,
        session_id: Option<String>,
        scanned_files: usize,
    },
    Git {
        output: GitCommandOutput,
    },
    WriteFileCas {
        outcome: SaveOutcome,
    },
    BeginWriteFileCas {
        outcome: WriteStartOutcome,
    },
    WriteFileChunk {
        upload_id: String,
        accepted: u64,
    },
    FinishWriteFileCas {
        outcome: SaveOutcome,
    },
    AbortWriteFileCas {
        upload_id: String,
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
    fn round_trips_scan_cursor_request() {
        let request = RpcMessage::Request {
            id: 11,
            request: Request::Scan {
                limit: 128,
                after: Some("src/main.rs".to_string()),
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn round_trips_grep_page_request() {
        let request = RpcMessage::Request {
            id: 12,
            request: Request::Grep {
                query: "needle".to_string(),
                limit: 50,
                after: Some("src/lib.rs".to_string()),
                max_files: Some(128),
                max_file_bytes: Some(512 * 1024),
                max_total_bytes: Some(8 * 1024 * 1024),
                session_id: Some("grep-7".to_string()),
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn round_trips_grep_page_response() {
        let response = RpcMessage::Response {
            id: 13,
            response: Response::Grep {
                hits: vec![SearchHit {
                    path: "src/lib.rs".to_string(),
                    line: 7,
                    column: 3,
                    text: "needle".to_string(),
                }],
                truncated: true,
                next_after: Some("src/lib.rs".to_string()),
                session_id: Some("grep-7".to_string()),
                scanned_files: 128,
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &response).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn round_trips_git_requests_and_response() {
        let requests = [
            RpcMessage::Request {
                id: 21,
                request: Request::GitStatus {
                    paths: vec!["src/lib.rs".to_string()],
                    max_output_bytes: 1024,
                },
            },
            RpcMessage::Request {
                id: 22,
                request: Request::GitDiff {
                    path: Some("src/lib.rs".to_string()),
                    cached: false,
                    max_output_bytes: 2048,
                },
            },
            RpcMessage::Request {
                id: 23,
                request: Request::GitBlame {
                    path: "src/lib.rs".to_string(),
                    max_output_bytes: 4096,
                },
            },
        ];
        for message in requests {
            let mut bytes = Vec::new();
            write_frame(&mut bytes, &message).unwrap();
            let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
            assert_eq!(decoded, message);
        }

        let response = RpcMessage::Response {
            id: 24,
            response: Response::Git {
                output: GitCommandOutput {
                    stdout: " M src/lib.rs\n".to_string(),
                    stderr: String::new(),
                    status_code: Some(0),
                    truncated: false,
                },
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &response).unwrap();
        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, response);
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
    fn round_trips_chunked_write_request() {
        let request = RpcMessage::Request {
            id: 10,
            request: Request::BeginWriteFileCas {
                path: "large.bin".to_string(),
                expected_hash: Some("old".to_string()),
                content_hash: "new".to_string(),
                size: 4096,
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn round_trips_truncated_save_conflict_response() {
        let response = RpcMessage::Response {
            id: 11,
            response: Response::WriteFileCas {
                outcome: SaveOutcome::Conflict(SaveConflict {
                    path: "large.bin".to_string(),
                    expected_hash: Some("old".to_string()),
                    actual_hash: Some("new".to_string()),
                    remote_content: vec![1, 2, 3],
                    remote_content_truncated: true,
                    remote_size: Some(99),
                }),
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &response).unwrap();

        let decoded: RpcMessage = read_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn rejects_oversized_frame_before_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes());
        let result: Result<Request, FrameError> = read_frame(&mut Cursor::new(bytes));
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
    }
}
