//! Static-asset surface for the built-in admin UI.
//!
//! When the `embed-admin-ui` cargo feature is on, the binary embeds
//! the contents of `ui/dist/` (the React + Vite build output) via
//! `include_dir!`. Requests under `/admin/ui` are served from that
//! tree, with `index.html` returned for both `/admin/ui` and
//! `/admin/ui/` (and for any SPA route that does not match a real
//! file, so React Router style paths work without a server-side
//! rewrite map).
//!
//! When the feature is off, the same paths return a one-line 404 so
//! operators see exactly what to run to enable the embedded UI. The
//! default cargo build does not require a prior `pnpm build`.
//!
//! The route handler always returns `(status, content_type, body)`
//! tuples to match the existing admin dispatcher in `admin.rs`.
//! Binary assets (fonts, images) are not yet supported by the
//! dispatcher's `String` response shape; the scaffold ships text
//! assets (HTML, JS, CSS, JSON, SVG, source maps) which is enough
//! for a Vite-built SPA. Binary asset support is a follow-up.
//!
//! Real views (providers, models, routing-strategy preview, metrics
//! tiles, the chat playground) are deferred to follow-up tickets;
//! this module only wires the mount.

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
fn path_is_ours(path: &str) -> bool {
    path == UI_PREFIX || path.starts_with(&format!("{UI_PREFIX}/"))
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

/// Map a file extension to a `Content-Type` header value. Only the
/// extensions Vite emits for a default React + TS build are listed;
/// unknown extensions fall back to `application/octet-stream` so a
/// stray binary at least transfers correctly even if it cannot
/// render.
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
        assert!(body.contains("pnpm build"));
        assert!(body.contains("embed-admin-ui"));
    }
}
