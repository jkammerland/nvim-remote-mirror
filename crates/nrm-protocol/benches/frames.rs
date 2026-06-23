use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use nrm_protocol::{
    read_frame, write_frame, BatchReadFile, FileMeta, FrameError, Response, RpcMessage, SearchHit,
    MAX_FRAME_LEN,
};
use std::hint::black_box;
use std::io::Cursor;

fn large_mode() -> bool {
    std::env::var("NRM_PERF_LARGE").ok().as_deref() == Some("1")
}

fn meta(index: usize) -> FileMeta {
    FileMeta {
        path: format!("src/{:03}/file_{index:05}.rs", index / 1000),
        size: 32,
        mtime_ms: index as i64,
        mode: 0o100644,
        is_dir: false,
        is_symlink: false,
        hash: Some(format!("{index:064x}")),
    }
}

fn scan_response(count: usize) -> RpcMessage {
    RpcMessage::Response {
        id: 1,
        response: Response::Scan {
            entries: (0..count).map(meta).collect(),
            truncated: true,
        },
    }
}

fn read_files_response(file_count: usize, file_bytes: usize) -> RpcMessage {
    RpcMessage::Response {
        id: 2,
        response: Response::ReadFiles {
            files: (0..file_count)
                .map(|index| BatchReadFile {
                    path: meta(index).path,
                    content: vec![b'x'; file_bytes],
                    hash: format!("{index:064x}"),
                    meta: meta(index),
                })
                .collect(),
            errors: Vec::new(),
            truncated: false,
        },
    }
}

fn grep_response(hit_count: usize, text_bytes: usize) -> RpcMessage {
    RpcMessage::Response {
        id: 3,
        response: Response::Grep {
            hits: (0..hit_count)
                .map(|index| SearchHit {
                    path: meta(index).path,
                    line: 10,
                    column: 3,
                    text: "x".repeat(text_bytes),
                })
                .collect(),
            truncated: true,
            next_after: Some("src/999/file_99999.rs".to_string()),
            session_id: Some("bench-session".to_string()),
            scanned_files: hit_count,
        },
    }
}

fn encode_frame(message: RpcMessage) -> usize {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &message).unwrap();
    bytes.len()
}

fn protocol_frames(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_frames");
    group.sample_size(if large_mode() { 10 } else { 20 });

    let scan_count = if large_mode() { 50_000 } else { 10_000 };
    group.throughput(Throughput::Elements(scan_count as u64));
    group.bench_function(format!("scan_{scan_count}_metadata_rows"), |b| {
        b.iter_batched(
            || scan_response(scan_count),
            |message| black_box(encode_frame(message)),
            BatchSize::SmallInput,
        )
    });

    let file_bytes = if large_mode() {
        MAX_FRAME_LEN - (1024 * 1024)
    } else {
        1024 * 1024
    };
    group.throughput(Throughput::Bytes(file_bytes as u64));
    group.bench_function(format!("read_files_payload_{file_bytes}_bytes"), |b| {
        b.iter_batched(
            || read_files_response(1, file_bytes),
            |message| black_box(encode_frame(message)),
            BatchSize::LargeInput,
        )
    });

    group.throughput(Throughput::Elements(2_000));
    group.bench_function("grep_2000_hits", |b| {
        b.iter_batched(
            || grep_response(2_000, 80),
            |message| black_box(encode_frame(message)),
            BatchSize::SmallInput,
        )
    });

    let oversized_len = MAX_FRAME_LEN + 1;
    let oversized_frame = (oversized_len as u32).to_be_bytes();
    group.bench_function("reject_oversized_frame_before_allocation", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(oversized_frame);
            let error = read_frame::<_, RpcMessage>(&mut cursor).unwrap_err();
            assert!(matches!(error, FrameError::TooLarge(len) if len == oversized_len));
        })
    });

    group.finish();
}

criterion_group!(benches, protocol_frames);
criterion_main!(benches);
