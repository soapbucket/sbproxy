//! API versioning support.
//!
//! Extracts API version from URL path (/v1/, /v2/), Accept-Version header,
//! or query parameter (?version=2). Used by routing to select the correct
//! upstream for a given API version.
//!
//! Priority order: path > header > query parameter.

// --- Types ---

/// The source from which an API version was extracted.
#[derive(Debug, Clone, PartialEq)]
pub enum VersionSource {
    /// Version found in the URL path, e.g. `/v1/users` -> `"1"`.
    Path(String),
    /// Version found in the `Accept-Version` header, e.g. `Accept-Version: 2` -> `"2"`.
    Header(String),
    /// Version found in the `version` query parameter, e.g. `?version=3` -> `"3"`.
    Query(String),
    /// No version information found.
    None,
}

// --- Extraction helpers ---

/// Extract the version number from the leading path segment if it matches `/vN`.
///
/// Accepts paths like `/v1/users`, `/v2/api/items`, or `/V3/` (case-insensitive).
/// Returns the numeric portion as a string, e.g. `"1"`, `"2"`, `"42"`.
fn extract_path_version(path: &str) -> Option<String> {
    // Split on '/' and find the first non-empty segment.
    let first_segment = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .filter(|s| !s.is_empty())?;

    // The segment must start with 'v' or 'V' followed by one or more digits.
    let after_v = first_segment
        .strip_prefix('v')
        .or_else(|| first_segment.strip_prefix('V'))?;
    if !after_v.is_empty() && after_v.chars().all(|c| c.is_ascii_digit()) {
        Some(after_v.to_string())
    } else {
        None
    }
}

/// Extract the version from the `Accept-Version` header in the provided header list.
///
/// `headers` is a slice of `(name, value)` pairs. Header names are compared
/// case-insensitively. The value is trimmed of whitespace.
fn extract_header_version(headers: &[(String, String)]) -> Option<String> {
    headers.iter().find_map(|(name, value)| {
        if name.eq_ignore_ascii_case("accept-version") {
            let v = value.trim().to_string();
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        } else {
            None
        }
    })
}

/// Extract the `version` query parameter value from a query string.
///
/// Parses a URL query string such as `"foo=bar&version=2&other=x"`.
fn extract_query_version(query: &str) -> Option<String> {
    for part in query.split('&') {
        let mut iter = part.splitn(2, '=');
        let key = iter.next().unwrap_or("").trim();
        let value = iter.next().unwrap_or("").trim();
        if key.eq_ignore_ascii_case("version") && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

// --- Public API ---

/// Extract API version from a request.
///
/// Checks sources in priority order: path > header > query parameter.
/// Returns the first `VersionSource` found, or `VersionSource::None`.
pub fn extract_version(
    path: &str,
    headers: &[(String, String)],
    query: Option<&str>,
) -> VersionSource {
    // 1. Path takes highest priority.
    if let Some(v) = extract_path_version(path) {
        return VersionSource::Path(v);
    }

    // 2. Accept-Version header.
    if let Some(v) = extract_header_version(headers) {
        return VersionSource::Header(v);
    }

    // 3. Query parameter.
    if let Some(q) = query {
        if let Some(v) = extract_query_version(q) {
            return VersionSource::Query(v);
        }
    }

    VersionSource::None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_headers() -> Vec<(String, String)> {
        vec![]
    }

    fn header(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), value.to_string())]
    }

    // --- Path extraction ---

    #[test]
    fn path_v1_users() {
        let result = extract_version("/v1/users", &no_headers(), None);
        assert_eq!(result, VersionSource::Path("1".to_string()));
    }

    #[test]
    fn path_v2_api_items() {
        let result = extract_version("/v2/api/items", &no_headers(), None);
        assert_eq!(result, VersionSource::Path("2".to_string()));
    }

    #[test]
    fn path_v10_multi_digit() {
        let result = extract_version("/v10/resources", &no_headers(), None);
        assert_eq!(result, VersionSource::Path("10".to_string()));
    }

    #[test]
    fn path_v1_trailing_slash() {
        let result = extract_version("/v1/", &no_headers(), None);
        assert_eq!(result, VersionSource::Path("1".to_string()));
    }

    #[test]
    fn path_no_version_segment() {
        let result = extract_version("/api/users", &no_headers(), None);
        assert_eq!(result, VersionSource::None);
    }

    #[test]
    fn path_v_without_number_not_matched() {
        let result = extract_version("/version/users", &no_headers(), None);
        // "version" starts with 'v' but the rest is not all digits.
        assert_eq!(result, VersionSource::None);
    }

    #[test]
    fn path_root_no_version() {
        let result = extract_version("/", &no_headers(), None);
        assert_eq!(result, VersionSource::None);
    }

    // --- Header extraction ---

    #[test]
    fn header_accept_version() {
        let headers = header("Accept-Version", "2");
        let result = extract_version("/api/users", &headers, None);
        assert_eq!(result, VersionSource::Header("2".to_string()));
    }

    #[test]
    fn header_accept_version_case_insensitive() {
        let headers = header("accept-version", "3");
        let result = extract_version("/api/users", &headers, None);
        assert_eq!(result, VersionSource::Header("3".to_string()));
    }

    #[test]
    fn header_accept_version_trimmed() {
        let headers = header("Accept-Version", "  4  ");
        let result = extract_version("/api/users", &headers, None);
        assert_eq!(result, VersionSource::Header("4".to_string()));
    }

    #[test]
    fn header_unrelated_ignored() {
        let headers = header("Content-Type", "application/json");
        let result = extract_version("/api/users", &headers, None);
        assert_eq!(result, VersionSource::None);
    }

    // --- Query parameter extraction ---

    #[test]
    fn query_version_param() {
        let result = extract_version("/api/users", &no_headers(), Some("version=3"));
        assert_eq!(result, VersionSource::Query("3".to_string()));
    }

    #[test]
    fn query_version_among_other_params() {
        let result = extract_version(
            "/api/users",
            &no_headers(),
            Some("foo=bar&version=5&baz=qux"),
        );
        assert_eq!(result, VersionSource::Query("5".to_string()));
    }

    #[test]
    fn query_version_case_insensitive_key() {
        let result = extract_version("/api/users", &no_headers(), Some("VERSION=7"));
        assert_eq!(result, VersionSource::Query("7".to_string()));
    }

    #[test]
    fn no_query_returns_none() {
        let result = extract_version("/api/users", &no_headers(), None);
        assert_eq!(result, VersionSource::None);
    }

    #[test]
    fn query_without_version_key_returns_none() {
        let result = extract_version("/api/users", &no_headers(), Some("foo=1&bar=2"));
        assert_eq!(result, VersionSource::None);
    }

    // --- Priority: path > header > query ---

    #[test]
    fn path_beats_header() {
        let headers = header("Accept-Version", "99");
        let result = extract_version("/v1/users", &headers, Some("version=42"));
        assert_eq!(result, VersionSource::Path("1".to_string()));
    }

    #[test]
    fn header_beats_query() {
        let headers = header("Accept-Version", "2");
        let result = extract_version("/api/users", &headers, Some("version=9"));
        assert_eq!(result, VersionSource::Header("2".to_string()));
    }

    #[test]
    fn query_used_when_no_path_or_header() {
        let result = extract_version("/api/users", &no_headers(), Some("version=6"));
        assert_eq!(result, VersionSource::Query("6".to_string()));
    }

    // --- None case ---

    #[test]
    fn no_version_anywhere_returns_none() {
        let result = extract_version("/api/users", &no_headers(), Some("foo=bar"));
        assert_eq!(result, VersionSource::None);
    }

    #[test]
    fn all_empty_returns_none() {
        let result = extract_version("", &no_headers(), None);
        assert_eq!(result, VersionSource::None);
    }
}
