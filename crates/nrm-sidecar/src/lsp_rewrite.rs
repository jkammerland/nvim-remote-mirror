use anyhow::Result;
use serde_json::Value;

pub(crate) fn rewrite_lsp_body(body: &[u8], from_prefix: &str, to_prefix: &str) -> Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(body)?;
    rewrite_lsp_json(&mut value, None, from_prefix, to_prefix);
    Ok(serde_json::to_vec(&value)?)
}

fn rewrite_lsp_json(value: &mut Value, key: Option<&str>, from_prefix: &str, to_prefix: &str) {
    match value {
        Value::String(text) => {
            if key.map(is_lsp_uri_key).unwrap_or(false) {
                if let Some(rewritten) = rewrite_lsp_uri(text, from_prefix, to_prefix) {
                    *text = rewritten;
                }
            } else if key.map(is_lsp_path_key).unwrap_or(false) {
                if let Some(rewritten) = rewrite_lsp_path(text, from_prefix, to_prefix) {
                    *text = rewritten;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite_lsp_json(value, key, from_prefix, to_prefix);
            }
        }
        Value::Object(map) => {
            let entries = std::mem::take(map);
            for (entry_key, mut entry_value) in entries {
                rewrite_lsp_json(&mut entry_value, Some(&entry_key), from_prefix, to_prefix);
                let rewritten_key = rewrite_lsp_object_key(&entry_key, from_prefix, to_prefix);
                if let Some(existing) = map.get_mut(&rewritten_key) {
                    merge_lsp_collision(existing, entry_value);
                } else {
                    map.insert(rewritten_key, entry_value);
                }
            }
        }
        _ => {}
    }
}

fn merge_lsp_collision(existing: &mut Value, incoming: Value) {
    match (existing, incoming) {
        (Value::Array(existing), Value::Array(mut incoming)) => existing.append(&mut incoming),
        (Value::Object(existing), Value::Object(incoming)) => {
            for (key, value) in incoming {
                if let Some(existing_value) = existing.get_mut(&key) {
                    merge_lsp_collision(existing_value, value);
                } else {
                    existing.insert(key, value);
                }
            }
        }
        _ => {}
    }
}

fn rewrite_lsp_object_key(key: &str, from_prefix: &str, to_prefix: &str) -> String {
    rewrite_lsp_uri(key, from_prefix, to_prefix).unwrap_or_else(|| key.to_string())
}

fn rewrite_lsp_uri(text: &str, from_prefix: &str, to_prefix: &str) -> Option<String> {
    if text.chars().any(char::is_whitespace) {
        return None;
    }
    let from_style = path_style(from_prefix);
    for (from_uri, to_uri) in path_to_file_uri_prefix_pairs(from_prefix, to_prefix) {
        if let Some(suffix) = strip_uri_prefix_with_boundary(text, &from_uri, from_style) {
            if !uri_suffix_has_no_dot_segments(
                suffix,
                traversal_path_style(path_style(from_prefix), path_style(to_prefix)),
            ) {
                return None;
            }
            let separator = if from_uri.ends_with('/')
                && !to_uri.ends_with('/')
                && !suffix.is_empty()
                && !suffix.starts_with(['?', '#'])
            {
                "/"
            } else {
                ""
            };
            return Some(format!("{to_uri}{separator}{suffix}"));
        }
    }
    None
}

fn rewrite_lsp_path(text: &str, from_prefix: &str, to_prefix: &str) -> Option<String> {
    let from_style = path_style(from_prefix);
    let suffix = strip_path_prefix_with_boundary(text, from_prefix, from_style)?;
    if !path_has_no_dot_segments(
        suffix,
        traversal_path_style(from_style, path_style(to_prefix)),
    ) {
        return None;
    }
    Some(join_rewritten_path(to_prefix, suffix, from_style))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathStyle {
    Posix,
    Windows,
}

fn path_style(path: &str) -> PathStyle {
    let bytes = path.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
    {
        PathStyle::Windows
    } else {
        PathStyle::Posix
    }
}

fn strip_path_prefix_with_boundary<'a>(
    text: &'a str,
    prefix: &str,
    style: PathStyle,
) -> Option<&'a str> {
    let candidate = text.get(..prefix.len())?;
    let matches = match style {
        PathStyle::Posix => candidate == prefix,
        PathStyle::Windows => windows_path_prefix_eq(candidate, prefix),
    };
    if !matches {
        return None;
    }

    let suffix = &text[prefix.len()..];
    if suffix.is_empty() || prefix.ends_with(path_separators(style)) {
        return Some(suffix);
    }
    suffix
        .chars()
        .next()
        .filter(|ch| path_separators(style).contains(ch))
        .map(|_| suffix)
}

fn windows_path_prefix_eq(candidate: &str, prefix: &str) -> bool {
    candidate
        .as_bytes()
        .iter()
        .zip(prefix.as_bytes())
        .enumerate()
        .all(|(index, (left, right))| {
            if matches!(left, b'/' | b'\\') && matches!(right, b'/' | b'\\') {
                true
            } else if index == 0 && prefix.as_bytes().get(1) == Some(&b':') {
                left.eq_ignore_ascii_case(right)
            } else {
                left == right
            }
        })
}

fn path_separators(style: PathStyle) -> &'static [char] {
    match style {
        PathStyle::Posix => &['/'],
        PathStyle::Windows => &['/', '\\'],
    }
}

fn traversal_path_style(from_style: PathStyle, to_style: PathStyle) -> PathStyle {
    if from_style == PathStyle::Windows || to_style == PathStyle::Windows {
        PathStyle::Windows
    } else {
        PathStyle::Posix
    }
}

fn path_has_no_dot_segments(path: &str, style: PathStyle) -> bool {
    !path
        .split(path_separators(style))
        .any(|segment| matches!(segment, "." | ".."))
}

fn uri_suffix_has_no_dot_segments(suffix: &str, style: PathStyle) -> bool {
    let path_end = suffix.find(['?', '#']).unwrap_or(suffix.len());
    let decoded = match strict_percent_decode(&suffix.as_bytes()[..path_end]) {
        Some(decoded) => decoded,
        None => return false,
    };
    !decoded
        .split(|byte| uri_path_separator(*byte, style))
        .any(|segment| segment == b"." || segment == b"..")
}

fn uri_path_separator(byte: u8, style: PathStyle) -> bool {
    byte == b'/' || (style == PathStyle::Windows && byte == b'\\')
}

fn strict_percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'%' {
            decoded.push(input[index]);
            index += 1;
            continue;
        }
        let high = decode_hex_digit(*input.get(index + 1)?)?;
        let low = decode_hex_digit(*input.get(index + 2)?)?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    Some(decoded)
}

fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn join_rewritten_path(to_prefix: &str, suffix: &str, from_style: PathStyle) -> String {
    if suffix.is_empty() {
        return to_prefix.to_string();
    }

    let to_style = path_style(to_prefix);
    let separator = match to_style {
        PathStyle::Posix => '/',
        PathStyle::Windows if to_prefix.as_bytes().get(2) == Some(&b'\\') => '\\',
        PathStyle::Windows => '/',
    };
    let relative = suffix.trim_start_matches(path_separators(from_style));
    let mut normalized = String::with_capacity(relative.len());
    for ch in relative.chars() {
        if ch == '/' || (from_style == PathStyle::Windows && ch == '\\') {
            normalized.push(separator);
        } else {
            normalized.push(ch);
        }
    }

    let base = to_prefix.trim_end_matches(['/', '\\']);
    if base.is_empty() && to_prefix.starts_with('/') {
        format!("/{normalized}")
    } else {
        format!("{base}{separator}{normalized}")
    }
}

fn strip_uri_prefix_with_boundary<'a>(
    text: &'a str,
    prefix: &str,
    style: PathStyle,
) -> Option<&'a str> {
    let candidate = text.get(..prefix.len())?;
    if !uri_prefix_eq(candidate, prefix, style) {
        return None;
    }
    let suffix = &text[prefix.len()..];
    if suffix.is_empty()
        || prefix.ends_with('/')
        || suffix
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, '/' | '?' | '#'))
    {
        Some(suffix)
    } else {
        None
    }
}

fn uri_prefix_eq(candidate: &str, prefix: &str, style: PathStyle) -> bool {
    if candidate.len() != prefix.len() {
        return false;
    }
    let candidate = candidate.as_bytes();
    let prefix = prefix.as_bytes();
    let windows_drive_index = (style == PathStyle::Windows
        && prefix.get(..8) == Some(b"file:///")
        && prefix.get(9) == Some(&b':'))
    .then_some(8);

    let mut index = 0;
    while index < prefix.len() {
        if prefix[index] == b'%' {
            if candidate[index] != b'%'
                || decode_hex_digit(*candidate.get(index + 1).unwrap_or(&0))
                    != decode_hex_digit(*prefix.get(index + 1).unwrap_or(&0))
                || decode_hex_digit(*candidate.get(index + 2).unwrap_or(&0))
                    != decode_hex_digit(*prefix.get(index + 2).unwrap_or(&0))
            {
                return false;
            }
            index += 3;
            continue;
        }
        let equivalent = if index < b"file://".len() || windows_drive_index == Some(index) {
            candidate[index].eq_ignore_ascii_case(&prefix[index])
        } else {
            candidate[index] == prefix[index]
        };
        if !equivalent {
            return false;
        }
        index += 1;
    }
    true
}

fn is_lsp_path_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "path"
        || key == "file"
        || key == "filename"
        || key == "directory"
        || key == "dir"
        || key == "cwd"
        || key.ends_with("path")
        || key.ends_with("filepath")
        || key.ends_with("file_path")
        || key.ends_with("filename")
        || key.ends_with("file_name")
        || key.ends_with("directory")
}

fn is_lsp_uri_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "uri" || key.ends_with("uri")
}

fn path_to_file_uri_prefix_pairs(from_prefix: &str, to_prefix: &str) -> Vec<(String, String)> {
    let from_prefix = file_uri_path(from_prefix);
    let to_prefix = file_uri_path(to_prefix);
    let mut pairs = vec![(
        format!("file://{from_prefix}"),
        format!("file://{to_prefix}"),
    )];
    let encoded = (
        format!("file://{}", percent_encode_uri_path(&from_prefix)),
        format!("file://{}", percent_encode_uri_path(&to_prefix)),
    );
    if encoded != pairs[0] {
        pairs.insert(0, encoded);
    }
    pairs
}

fn file_uri_path(path: &str) -> String {
    if path_style(path) == PathStyle::Windows {
        format!("/{}", path.replace('\\', "/"))
    } else {
        path.to_string()
    }
}

fn percent_encode_uri_path(path: &str) -> String {
    let mut encoded = String::new();
    for byte in path.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b':' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(*byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde_json::{json, Value};

    use super::rewrite_lsp_body;

    fn rewrite(value: Value, from_prefix: &str, to_prefix: &str) -> Value {
        let body = serde_json::to_vec(&value).unwrap();
        let rewritten = rewrite_lsp_body(&body, from_prefix, to_prefix).unwrap();
        serde_json::from_slice(&rewritten).unwrap()
    }

    #[test]
    fn rewrites_windows_forward_and_backslash_paths_to_local_paths() {
        let rewritten = rewrite(
            json!({
                "path": "B:/repo/src/main.rs",
                "filePath": r"B:\repo\src\lib.rs",
                "cwd": "b:/repo/tools",
                "caseDistinctPath": "B:/REPO/tools",
                "directory": r"B:\repository",
                "otherPath": "B:/repo-other/src",
                "message": r"B:\repo\src\lib.rs stays prose"
            }),
            "B:/repo",
            "/local/mirror",
        );

        assert_eq!(rewritten["path"], "/local/mirror/src/main.rs");
        assert_eq!(rewritten["filePath"], "/local/mirror/src/lib.rs");
        assert_eq!(rewritten["cwd"], "/local/mirror/tools");
        assert_eq!(rewritten["caseDistinctPath"], "B:/REPO/tools");
        assert_eq!(rewritten["directory"], r"B:\repository");
        assert_eq!(rewritten["otherPath"], "B:/repo-other/src");
        assert_eq!(rewritten["message"], r"B:\repo\src\lib.rs stays prose");
    }

    #[test]
    fn rewrites_windows_file_uris_and_workspace_edit_keys() {
        let rewritten = rewrite(
            json!({
                "uri": "FILE:///b:/repo/src/main.rs?version=1#L2",
                "caseDistinctUri": "file:///B:/REPO/src/main.rs",
                "targetUri": "file:///B:/repository/src/not-ours.rs",
                "changes": {
                    "file:///B:/repo/src/lib.rs": [{"newText": "x"}],
                    "file:///B:/REPO/src/lib.rs": [{"newText": "case-distinct"}],
                    "file:///B:/repo-other/src/lib.rs": [{"newText": "y"}]
                }
            }),
            r"B:\repo",
            "/local/mirror",
        );

        assert_eq!(
            rewritten["uri"],
            "file:///local/mirror/src/main.rs?version=1#L2"
        );
        assert_eq!(rewritten["caseDistinctUri"], "file:///B:/REPO/src/main.rs");
        assert_eq!(
            rewritten["targetUri"],
            "file:///B:/repository/src/not-ours.rs"
        );
        let changes = rewritten["changes"].as_object().unwrap();
        assert!(changes.contains_key("file:///local/mirror/src/lib.rs"));
        assert!(changes.contains_key("file:///B:/REPO/src/lib.rs"));
        assert!(changes.contains_key("file:///B:/repo-other/src/lib.rs"));
    }

    #[test]
    fn reverse_mapping_emits_canonical_windows_paths_and_file_uris() {
        let rewritten = rewrite(
            json!({
                "rootPath": "/local/mirror",
                "path": "/local/mirror/src/main.rs",
                "uri": "file:///local/mirror/src/main.rs",
                "changes": {
                    "file:///local/mirror/src/lib.rs": [{"newText": "x"}]
                }
            }),
            "/local/mirror",
            "B:/repo",
        );

        assert_eq!(rewritten["rootPath"], "B:/repo");
        assert_eq!(rewritten["path"], "B:/repo/src/main.rs");
        assert_eq!(rewritten["uri"], "file:///B:/repo/src/main.rs");
        assert!(rewritten["changes"]
            .as_object()
            .unwrap()
            .contains_key("file:///B:/repo/src/lib.rs"));
    }

    #[test]
    fn windows_uri_mapping_percent_encodes_each_side_without_losing_boundaries() {
        let remote = rewrite(
            json!({"uri": "file:///local/mirror%20space/src/main.rs"}),
            "/local/mirror space",
            "B:/repo space",
        );
        assert_eq!(remote["uri"], "file:///B:/repo%20space/src/main.rs");

        let local = rewrite(remote, "B:/repo space", "/local/mirror space");
        assert_eq!(local["uri"], "file:///local/mirror%20space/src/main.rs");
    }

    #[test]
    fn windows_drive_root_rewrites_paths_and_uris() {
        let rewritten = rewrite(
            json!({
                "path": r"B:\src\main.rs",
                "uri": "file:///B:/src/main.rs"
            }),
            "B:/",
            "/local/drive-b",
        );

        assert_eq!(rewritten["path"], "/local/drive-b/src/main.rs");
        assert_eq!(rewritten["uri"], "file:///local/drive-b/src/main.rs");
    }

    #[test]
    fn rejects_plain_dot_segments_in_both_windows_mapping_directions() {
        let local = rewrite(
            json!({
                "forwardParentPath": "B:/repo/../outside.rs",
                "backslashParentPath": r"B:\repo\..\outside.rs",
                "forwardCurrentPath": "B:/repo/./inside.rs",
                "safeHiddenPath": "B:/repo/.hidden/inside.rs"
            }),
            "B:/repo",
            "/local/mirror",
        );
        assert_eq!(local["forwardParentPath"], "B:/repo/../outside.rs");
        assert_eq!(local["backslashParentPath"], r"B:\repo\..\outside.rs");
        assert_eq!(local["forwardCurrentPath"], "B:/repo/./inside.rs");
        assert_eq!(local["safeHiddenPath"], "/local/mirror/.hidden/inside.rs");

        let remote = rewrite(
            json!({
                "parentPath": "/local/mirror/../outside.rs",
                "currentPath": "/local/mirror/./inside.rs",
                "backslashParentPath": r"/local/mirror/src\..\outside.rs",
                "safePath": "/local/mirror/src/inside.rs"
            }),
            "/local/mirror",
            "B:/repo",
        );
        assert_eq!(remote["parentPath"], "/local/mirror/../outside.rs");
        assert_eq!(remote["currentPath"], "/local/mirror/./inside.rs");
        assert_eq!(
            remote["backslashParentPath"],
            r"/local/mirror/src\..\outside.rs"
        );
        assert_eq!(remote["safePath"], "B:/repo/src/inside.rs");
    }

    #[test]
    fn rejects_decoded_uri_dot_segments_and_preserves_valid_suffix_bytes() {
        let local = rewrite(
            json!({
                "rawParentUri": "file:///B:/repo/../outside.rs?keep=..#fragment",
                "encodedParentUri": "file:///B:/repo/%2e%2E/outside.rs?keep=%2E%2E#fragment",
                "encodedBackslashUri": "file:///B:/repo/src%5c%2E%2e%5coutside.rs",
                "malformedUri": "file:///B:/repo/src%2G/file.rs",
                "safeUri": "file:///B:/repo/src%20dir/file.rs?keep=%2E%2E#fragment"
            }),
            "B:/repo",
            "/local/mirror",
        );
        assert_eq!(
            local["rawParentUri"],
            "file:///B:/repo/../outside.rs?keep=..#fragment"
        );
        assert_eq!(
            local["encodedParentUri"],
            "file:///B:/repo/%2e%2E/outside.rs?keep=%2E%2E#fragment"
        );
        assert_eq!(
            local["encodedBackslashUri"],
            "file:///B:/repo/src%5c%2E%2e%5coutside.rs"
        );
        assert_eq!(local["malformedUri"], "file:///B:/repo/src%2G/file.rs");
        assert_eq!(
            local["safeUri"],
            "file:///local/mirror/src%20dir/file.rs?keep=%2E%2E#fragment"
        );

        let remote = rewrite(
            json!({
                "rawCurrentUri": "file:///local/mirror/./inside.rs",
                "encodedParentUri": "file:///local/mirror/%2E%2e/outside.rs",
                "encodedPosixBackslashUri": "file:///local/mirror/src%5C..%5Cname.rs",
                "safeUri": "file:///local/mirror/src%20dir/file.rs?keep=..#fragment"
            }),
            "/local/mirror",
            "B:/repo",
        );
        assert_eq!(remote["rawCurrentUri"], "file:///local/mirror/./inside.rs");
        assert_eq!(
            remote["encodedParentUri"],
            "file:///local/mirror/%2E%2e/outside.rs"
        );
        assert_eq!(
            remote["encodedPosixBackslashUri"],
            "file:///local/mirror/src%5C..%5Cname.rs"
        );
        assert_eq!(
            remote["safeUri"],
            "file:///B:/repo/src%20dir/file.rs?keep=..#fragment"
        );
    }

    #[test]
    fn encoded_powershell_relay_uses_binary_standard_streams() {
        let launch = crate::remote_host::powershell_process_command(
            "rust-analyzer.exe",
            &["--stdio".to_string()],
            Some("B:/repo"),
            None,
        )
        .unwrap();
        let encoded = launch.command.split_whitespace().last().unwrap();
        let bytes = STANDARD.decode(encoded).unwrap();
        let mut chunks = bytes.chunks_exact(2);
        let utf16 = chunks
            .by_ref()
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        assert!(chunks.remainder().is_empty());
        let script = String::from_utf16(&utf16).unwrap();

        assert!(script.contains("GZipStream"));
        assert!(script.contains("OpenStandardInput(1)"));
        assert!(script.contains("Read-NrmBytes"));
        assert!(script.contains("ScriptBlock"));
        assert!(!launch.stdin_prefix.is_empty());

        let relay = crate::remote_host::POWERSHELL_PROCESS_SCRIPT_SOURCE;
        assert!(relay.contains("GetStdHandle(-10)"));
        assert!(relay.contains("CreateProcess("));
        assert!(relay.contains("AnonymousPipeServerStream"));
        assert!(relay.contains("PROC_THREAD_ATTRIBUTE_HANDLE_LIST"));
        assert!(relay.contains("PROC_THREAD_ATTRIBUTE_JOB_LIST"));
        assert!(relay.contains("ReadFile(input"));
        assert!(relay.contains("WriteFile(destination"));
        assert!(relay.contains("FlushFileBuffers(destination)"));
        assert!(!relay.contains("CopyToAsync"));
        assert!(!relay.contains("System.Diagnostics.Process"));
        assert!(!relay.contains("[Console]::WriteLine"));
    }
}
