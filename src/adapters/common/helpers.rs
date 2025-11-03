use itertools::Itertools;

/// Formats `bytes` as a colon-separated string of hex values, with `bytes_per_line` elements on
/// each line, indented by `indent` spaces.
pub(crate) fn format_hex_bytes(bytes_per_line: usize, indent: usize, bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .chunks(bytes_per_line)
        .into_iter()
        .map(|mut row| format!("{:indent$}{}", "", row.join(":")))
        .join(":\n")
}
