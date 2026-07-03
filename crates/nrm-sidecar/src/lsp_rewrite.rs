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
            if let Some(rewritten) = rewrite_lsp_uri(text, from_prefix, to_prefix) {
                *text = rewritten;
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
                map.insert(
                    rewrite_lsp_object_key(&entry_key, from_prefix, to_prefix),
                    entry_value,
                );
            }
        }
        _ => {}
    }
}

fn rewrite_lsp_object_key(key: &str, from_prefix: &str, to_prefix: &str) -> String {
    rewrite_lsp_uri(key, from_prefix, to_prefix)
        .or_else(|| rewrite_lsp_path(key, from_prefix, to_prefix))
        .unwrap_or_else(|| key.to_string())
}

fn rewrite_lsp_uri(text: &str, from_prefix: &str, to_prefix: &str) -> Option<String> {
    for (from_uri, to_uri) in path_to_file_uri_prefix_pairs(from_prefix, to_prefix) {
        if let Some(suffix) = strip_prefix_with_boundary(text, &from_uri, &['/', '?', '#']) {
            return Some(format!("{to_uri}{suffix}"));
        }
    }
    None
}

fn rewrite_lsp_path(text: &str, from_prefix: &str, to_prefix: &str) -> Option<String> {
    strip_prefix_with_boundary(text, from_prefix, &['/', '\\'])
        .map(|suffix| format!("{to_prefix}{suffix}"))
}

fn strip_prefix_with_boundary<'a>(
    text: &'a str,
    prefix: &str,
    boundaries: &[char],
) -> Option<&'a str> {
    let suffix = text.strip_prefix(prefix)?;
    if suffix
        .chars()
        .next()
        .map(|ch| boundaries.contains(&ch))
        .unwrap_or(true)
    {
        Some(suffix)
    } else {
        None
    }
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

fn path_to_file_uri_prefix_pairs(from_prefix: &str, to_prefix: &str) -> Vec<(String, String)> {
    let mut pairs = vec![(
        format!("file://{}", from_prefix),
        format!("file://{}", to_prefix),
    )];
    let encoded = (
        format!("file://{}", percent_encode_uri_path(from_prefix)),
        format!("file://{}", percent_encode_uri_path(to_prefix)),
    );
    if encoded != pairs[0] {
        pairs.insert(0, encoded);
    }
    pairs
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
