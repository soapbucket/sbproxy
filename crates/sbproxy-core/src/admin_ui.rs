//! Static-asset surface for the built-in admin UI.
//!
//! When the `embed-admin-ui` cargo feature is on, the binary embeds
//! the contents of `ui/dist/` (the Vue + Vite build output) via
//! `include_dir!`. Requests under `/admin/ui` are served from that
//! tree, with `index.html` returned for both `/admin/ui` and
//! `/admin/ui/` (and for any SPA route that does not match a real
//! file, so Vue Router history-mode paths work without a server-side
//! rewrite map).
//!
//! When the feature is off, the same paths return a one-line 404 so
//! operators see exactly what to run to enable the embedded UI. The
//! default cargo build does not require a prior `npm build`.
//!
//! [`dispatch_bytes`] returns `(status, content_type, Vec<u8>)` so the
//! admin server can serve a real Vite bundle: binary assets (woff2
//! fonts, png/webp images, wasm) are returned byte-for-byte, not just
//! the text assets (HTML, JS, CSS, JSON, SVG, source maps). The older
//! [`dispatch`] returns a `String` body and is kept for the callers
//! that only need text (and for the no-feature 404 path).

/// Path prefix the admin server uses for the built-in UI. Mounted on
/// the existing admin dispatcher in [`crate::admin::handle_admin_request`]
/// so the dashboard sits next to `/admin/reload`, `/admin/drift`, and
/// the per-tab JSON endpoints.
pub const UI_PREFIX: &str = "/admin/ui";

/// Body returned when the binary was built without `embed-admin-ui`.
/// Operators see this when they hit the admin port at `/admin/ui`.
/// The text mirrors the README guidance so a stranded operator can
/// run the right command without reading any docs.
const NOT_BUILT_MESSAGE: &str = "Admin UI not built. Run `cd ui && pnpm install && pnpm build` \
     then rebuild with `--features embed-admin-ui`.";

/// Dispatch a `/admin/ui[/...]` request. Returns `None` when the
/// path does not start with the UI prefix, leaving the caller to
/// fall through to the next route. Returns `Some((status, ct, body))`
/// when the path is ours so the admin server can short-circuit.
///
/// The default cargo build path returns a 404 with a fixed
/// `NOT_BUILT_MESSAGE` (a private constant), and the
/// `embed-admin-ui` build path delegates to `serve_embedded` (only
/// compiled in under that feature). Both are private to this
/// module; see the source for the exact bodies.
pub fn dispatch(method: &str, path: &str) -> Option<(u16, &'static str, String)> {
    if !path_is_ours(path) {
        return None;
    }
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return Some((
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        ));
    }
    #[cfg(feature = "embed-admin-ui")]
    {
        Some(serve_embedded(path))
    }
    #[cfg(not(feature = "embed-admin-ui"))]
    {
        Some((
            404,
            "text/plain; charset=utf-8",
            NOT_BUILT_MESSAGE.to_string(),
        ))
    }
}

/// Path-matching helper. `/admin/ui` (no trailing slash) and any
/// subpath under `/admin/ui/` belong to this module. We accept the
/// no-slash form so a single href like `<a href="/admin/ui">` does
/// not 404 before the SPA loads.
pub fn path_is_ours(path: &str) -> bool {
    path == UI_PREFIX || path.starts_with(&format!("{UI_PREFIX}/"))
}

/// Byte-body variant of [`dispatch`], used by the admin server to serve
/// a real Vite bundle including binary assets (fonts, images, wasm)
/// that a `String` body would corrupt. Returns `None` when the path is
/// not ours; otherwise `Some((status, content_type, bytes))`. Auth is
/// enforced by the caller before this is reached (same Basic-auth gate
/// as every other `/admin/*` route).
pub fn dispatch_bytes(method: &str, path: &str) -> Option<(u16, &'static str, Vec<u8>)> {
    if !path_is_ours(path) {
        return None;
    }
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return Some((
            405,
            "application/json",
            br#"{"error":"method not allowed"}"#.to_vec(),
        ));
    }
    #[cfg(feature = "embed-admin-ui")]
    {
        Some(serve_embedded_bytes(path))
    }
    #[cfg(not(feature = "embed-admin-ui"))]
    {
        Some((
            404,
            "text/plain; charset=utf-8",
            NOT_BUILT_MESSAGE.as_bytes().to_vec(),
        ))
    }
}

/// Serve an asset from the embedded `ui/dist/` tree. SPA semantics:
/// missing files fall back to `index.html` so client-side router
/// paths work without a server-side rewrite map. The feature-gated
/// implementation lives behind a `cfg` so the `include_dir!` call
/// does not appear in the default-feature build path at all.
#[cfg(feature = "embed-admin-ui")]
fn serve_embedded(path: &str) -> (u16, &'static str, String) {
    use include_dir::{include_dir, Dir};
    // The macro path is relative to the calling file. From
    // `crates/sbproxy-core/src/admin_ui.rs` to the workspace
    // `ui/dist/` directory is three `../` hops.
    static UI_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../ui/dist");

    // Strip the `/admin/ui` prefix to land on a relative path inside
    // the embedded tree. The empty / slash-only forms route to
    // `index.html`.
    let relative = path
        .strip_prefix(UI_PREFIX)
        .map(|p| p.trim_start_matches('/'))
        .unwrap_or("");
    let lookup = if relative.is_empty() {
        "index.html"
    } else {
        relative
    };

    if let Some(file) = UI_DIR.get_file(lookup) {
        let content_type = content_type_for(lookup);
        // Lossy decode: the dispatcher response shape is `String`. The
        // scaffold ships text assets only (HTML, JS, CSS, SVG, JSON,
        // source maps). Binary assets (fonts, images) are a follow-up;
        // until then a lossy decode keeps the build green if a binary
        // accidentally lands in `ui/dist/`. The replacement-char will
        // be visible in the browser so the regression is obvious.
        let body = String::from_utf8_lossy(file.contents()).into_owned();
        return (200, content_type, body);
    }

    // SPA fallback: any unknown path inside `/admin/ui` serves
    // `index.html` so React Router style routes work without a
    // rewrite rule. The 200 is intentional; a 404 here would break
    // direct-link / refresh on a client-side route.
    if let Some(file) = UI_DIR.get_file("index.html") {
        let body = String::from_utf8_lossy(file.contents()).into_owned();
        return (200, "text/html; charset=utf-8", body);
    }

    // Fallthrough: `ui/dist/` exists but is empty (the `.gitkeep`
    // case in a fresh checkout that has not run `pnpm build`). Send
    // back the same operator hint the no-feature build sends, so
    // the symptom matches.
    (
        404,
        "text/plain; charset=utf-8",
        NOT_BUILT_MESSAGE.to_string(),
    )
}

/// Serve an asset from the embedded `ui/dist/` tree as raw bytes (no
/// lossy UTF-8 decode), so binary assets survive. Same SPA fallback as
/// [`serve_embedded`]: a missing file serves `index.html` with a 200 so
/// client-side routes work on refresh / direct link.
#[cfg(feature = "embed-admin-ui")]
fn serve_embedded_bytes(path: &str) -> (u16, &'static str, Vec<u8>) {
    use include_dir::{include_dir, Dir};
    static UI_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../ui/dist");

    let relative = path
        .strip_prefix(UI_PREFIX)
        .map(|p| p.trim_start_matches('/'))
        .unwrap_or("");
    let lookup = if relative.is_empty() {
        "index.html"
    } else {
        relative
    };

    if let Some(file) = UI_DIR.get_file(lookup) {
        return (200, content_type_for(lookup), file.contents().to_vec());
    }
    if let Some(file) = UI_DIR.get_file("index.html") {
        return (200, "text/html; charset=utf-8", file.contents().to_vec());
    }
    (
        404,
        "text/plain; charset=utf-8",
        NOT_BUILT_MESSAGE.as_bytes().to_vec(),
    )
}

/// Map a file extension to a `Content-Type` header value. Covers the
/// text and binary assets a Vite build of the Vue app emits (JS/CSS/
/// HTML/JSON/SVG plus woff2/woff/ttf fonts, png/jpg/gif/ico/webp
/// images, and wasm); unknown extensions fall back to
/// `application/octet-stream` so a stray file at least transfers
/// correctly even if the browser cannot render it.
#[cfg(feature = "embed-admin-ui")]
fn content_type_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_matching_path_returns_none() {
        assert!(dispatch("GET", "/api/health").is_none());
        assert!(dispatch("GET", "/admin/reload").is_none());
        assert!(dispatch("GET", "/").is_none());
    }

    #[test]
    fn ui_prefix_is_ours() {
        assert!(path_is_ours("/admin/ui"));
        assert!(path_is_ours("/admin/ui/"));
        assert!(path_is_ours("/admin/ui/index.html"));
        assert!(path_is_ours("/admin/ui/assets/main.js"));
        // Sibling prefixes do not match.
        assert!(!path_is_ours("/admin/ui-other"));
        assert!(!path_is_ours("/admin"));
    }

    #[test]
    fn non_get_returns_405() {
        let (status, _, _) = dispatch("POST", "/admin/ui").expect("matched");
        assert_eq!(status, 405);
    }

    #[cfg(not(feature = "embed-admin-ui"))]
    #[test]
    fn default_build_returns_404_with_build_instructions() {
        let (status, ct, body) = dispatch("GET", "/admin/ui").expect("matched");
        assert_eq!(status, 404);
        assert_eq!(ct, "text/plain; charset=utf-8");
        assert!(body.contains("Admin UI not built"));
        assert!(body.contains("npm build"));
        assert!(body.contains("embed-admin-ui"));
    }

    #[test]
    fn dispatch_bytes_matches_only_ui_paths() {
        assert!(dispatch_bytes("GET", "/api/health").is_none());
        assert!(dispatch_bytes("GET", "/admin/ui").is_some());
        let (status, _, _) = dispatch_bytes("POST", "/admin/ui/assets/x.js").expect("matched");
        assert_eq!(status, 405);
    }

    #[cfg(not(feature = "embed-admin-ui"))]
    #[test]
    fn dispatch_bytes_default_build_is_404() {
        let (status, ct, body) = dispatch_bytes("GET", "/admin/ui").expect("matched");
        assert_eq!(status, 404);
        assert_eq!(ct, "text/plain; charset=utf-8");
        assert!(String::from_utf8_lossy(&body).contains("Admin UI not built"));
    }
}
