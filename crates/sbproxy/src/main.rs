//! sbproxy: AI Governance Gateway binary.
//!
//! Thin entrypoint that selects the rustls crypto provider, installs the
//! mimalloc allocator, parses CLI args, and hands the config path to
//! [`sbproxy_core::run`]. All real work happens in the workspace crates.

#![warn(missing_docs)]

use std::env;

// mimalloc is Microsoft's high-performance allocator. Typically 5-10% faster
// than glibc malloc on server workloads; negligible on allocation-light
// paths. See sbproxy-bench/docs/RUST_OPTIMIZATIONS.md A2.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // rustls 0.23 requires the process to select a CryptoProvider before any
    // TLS machinery initialises. We install `ring` because `ring` is already
    // a workspace dependency (used by sbproxy-vault, sbproxy-tls, and
    // sbproxy-modules) so no new crate graph risk. Without this, every proxy
    // that touches TLS panics at startup.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .compact()
        .init();

    let args: Vec<String> = env::args().collect();

    // --- --version / -V short-circuit ---
    //
    // Output shape: `sbproxy <semver> (rev <sha>, built <yyyy-mm-dd>)`.
    // CARGO_PKG_VERSION comes from the workspace `version`. The git SHA
    // and build date are embedded by build.rs at compile time.
    //
    // The output shape is load-bearing: the marketing site (Hero.vue)
    // advertises it, and Homebrew's `test do` block asserts on it. If
    // you change the format, fix Hero.vue and the homebrew formula in
    // lockstep.
    if matches!(
        args.get(1).map(String::as_str),
        Some("--version") | Some("-V") | Some("version")
    ) {
        println!(
            "sbproxy {} (rev {}, built {})",
            env!("CARGO_PKG_VERSION"),
            env!("SBPROXY_GIT_SHA"),
            env!("SBPROXY_BUILD_DATE"),
        );
        return;
    }

    // --- --help / -h / help short-circuit ---
    //
    // Print usage and exit 0 (vs the no-args case, which exits 1).
    if matches!(
        args.get(1).map(String::as_str),
        Some("--help") | Some("-h") | Some("help")
    ) {
        println!("{}", general_usage_str());
        return;
    }

    // --- `sbproxy validate <path>` subcommand (alias: `--check`) ---
    //
    // Parse and compile the config without starting the proxy. Useful in
    // CI to fail fast on a bad sb.yml before deploying.
    //
    // The `--check` form is documented in SUPPLY-CHAIN.md as a CI-friendly
    // verification step (`./sbproxy --config /path --check`); it dispatches
    // to the same handler as `validate <path>`.
    if matches!(args.get(1).map(String::as_str), Some("validate"))
        || args.iter().any(|a| a == "--check")
    {
        // For the `--check` form, strip --check from the argv so the
        // existing parser sees only `--config <path>` (or `-f <path>`,
        // or a positional path).
        let filtered: Vec<String> = args
            .iter()
            .skip(1)
            .filter(|a| a.as_str() != "--check" && a.as_str() != "validate")
            .cloned()
            .collect();
        match handle_validate_subcommand(&filtered) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("validate: {e:#}");
                std::process::exit(2);
            }
        }
    }

    // --- Wave 4 / G4.5..G4.8 wire: `sbproxy projections render` ---
    //
    // Per A4.1 § "Operator preview via CLI": loads the YAML config,
    // runs `compile_config`, runs `render_projections`, writes the
    // named document for the named hostname (default the first
    // origin) to stdout. No proxy starts; this is a pure render.
    if matches!(args.get(1).map(String::as_str), Some("projections")) {
        match handle_projections_subcommand(&args[2..]) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(2);
            }
        }
    }

    let config_path = parse_config_path(&args);

    match config_path {
        Some(path) => {
            if let Err(e) = sbproxy_core::run(path) {
                eprintln!("Fatal: {e:#}");
                std::process::exit(1);
            }
        }
        None => {
            eprintln!("Usage: sbproxy --config <path>");
            eprintln!("       sbproxy serve -f <path> [--log-level <level>]");
            eprintln!(
                "       sbproxy projections render --kind {{robots,llms,llms-full,licenses,tdmrep}} \\"
            );
            eprintln!("                                --config <path> [--hostname <h>]");
            std::process::exit(1);
        }
    }
}

/// Parse config file path from CLI args.
///
/// Supports:
/// ```text
/// sbproxy --config <path>
/// sbproxy serve -f <path> [--log-level <level>]
/// sbproxy <path>  # positional
/// ```
fn parse_config_path(args: &[String]) -> Option<&str> {
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-f" => {
                return args.get(i + 1).map(|s| s.as_str());
            }
            "serve" => {
                i += 1;
                continue;
            }
            "--log-level" | "--log-format" => {
                i += 2; // skip flag + value
                continue;
            }
            arg if !arg.starts_with('-') => {
                return Some(arg);
            }
            _ => {
                i += 1;
                continue;
            }
        }
    }
    None
}

// --- `projections` subcommand handling ---

/// Dispatch the `projections render` subcommand.
///
/// `args` is the slice after `projections` (so `args[0]` is typically
/// `render`). Returns an error suitable for `eprintln!`-ing on the
/// CLI; the caller exits with status 2 on error so shell pipelines
/// can distinguish CLI errors from proxy runtime errors (status 1).
fn handle_projections_subcommand(args: &[String]) -> anyhow::Result<()> {
    let subcommand = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!(usage_str()))?;
    match subcommand {
        "render" => handle_projections_render(&args[1..]),
        other => Err(anyhow::anyhow!(
            "unknown projections subcommand: {other}\n{}",
            usage_str()
        )),
    }
}

fn usage_str() -> &'static str {
    "usage: sbproxy projections render --kind {robots|llms|llms-full|licenses|tdmrep} \
     --config <path> [--hostname <h>]"
}

/// Top-level usage banner shown by `--help`/`-h`/`help` and by argument
/// errors. Distinct from `usage_str()` which is the projections-specific
/// help text.
fn general_usage_str() -> &'static str {
    "sbproxy: AI Governance Gateway
       One self-hostable runtime for AI traffic, APIs, MCP, and AI crawlers.

USAGE:
    sbproxy --config <path>
    sbproxy serve -f <path> [--log-level <level>]
    sbproxy validate <path>
    sbproxy --config <path> --check
    sbproxy projections render --kind {robots|llms|llms-full|licenses|tdmrep} \\
                               --config <path> [--hostname <h>]
    sbproxy --version
    sbproxy --help

DOCS:
    https://github.com/soapbucket/sbproxy/blob/main/docs/README.md"
}

/// Validate an `sb.yml` without starting the proxy. Returns Ok on a config
/// that loads and compiles cleanly; Err with a context-rich message
/// otherwise. Wired to the `sbproxy validate <path>` subcommand.
fn handle_validate_subcommand(args: &[String]) -> anyhow::Result<()> {
    let path = parse_validate_path(args).ok_or_else(|| {
        anyhow::anyhow!(
            "missing config path\n\nusage: sbproxy validate <path>\n   or: sbproxy validate --config <path>"
        )
    })?;
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config '{path}': {e}"))?;
    sbproxy_config::compile_config(&yaml)
        .map_err(|e| anyhow::anyhow!("config '{path}' did not compile:\n{e:#}"))?;
    println!("ok: {path} is a valid sbproxy config");
    Ok(())
}

/// Pluck the config path out of `validate`'s argv. Mirrors `parse_config_path`
/// but operates on the args AFTER `validate` has already been consumed.
fn parse_validate_path(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-f" => return args.get(i + 1).map(|s| s.as_str()),
            arg if !arg.starts_with('-') => return Some(arg),
            _ => i += 1,
        }
    }
    None
}

#[derive(Debug)]
struct RenderArgs {
    kind: String,
    config: String,
    hostname: Option<String>,
}

fn parse_render_args(args: &[String]) -> anyhow::Result<RenderArgs> {
    let mut kind: Option<String> = None;
    let mut config: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kind" | "-k" => {
                kind = args.get(i + 1).cloned();
                i += 2;
            }
            "--config" | "-c" | "-f" => {
                config = args.get(i + 1).cloned();
                i += 2;
            }
            "--hostname" | "-H" => {
                hostname = args.get(i + 1).cloned();
                i += 2;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown flag {other} for projections render"
                ));
            }
        }
    }
    let kind = kind.ok_or_else(|| anyhow::anyhow!("missing --kind"))?;
    let config = config.ok_or_else(|| anyhow::anyhow!("missing --config"))?;
    Ok(RenderArgs {
        kind,
        config,
        hostname,
    })
}

fn handle_projections_render(args: &[String]) -> anyhow::Result<()> {
    let render = parse_render_args(args)?;
    let yaml = std::fs::read_to_string(&render.config)
        .map_err(|e| anyhow::anyhow!("failed to read config '{}': {e}", render.config))?;
    let compiled = sbproxy_config::compile_config(&yaml)?;

    // The CLI uses a deterministic config_version of 0 so output is
    // reproducible across invocations, matching A4.1's "byte-for-byte
    // identical" preview contract for a given config.
    let docs = sbproxy_modules::projections::render_projections(&compiled, 0);

    // Pick the hostname: explicit flag wins; otherwise default to the
    // first origin in the compiled config so a single-origin config
    // works without extra arguments.
    let hostname = match render.hostname {
        Some(h) => h,
        None => compiled
            .origins
            .first()
            .map(|o| o.hostname.to_string())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no origins configured in '{}'; cannot pick a default hostname",
                    render.config
                )
            })?,
    };

    let body = lookup_projection(&docs, &render.kind, &hostname).ok_or_else(|| {
        anyhow::anyhow!(
            "no '{}' projection for hostname '{hostname}' (origin missing or has no \
             ai_crawl_control policy)",
            render.kind
        )
    })?;

    use std::io::Write as _;
    std::io::stdout().write_all(body.as_ref())?;
    std::io::stdout().flush()?;
    Ok(())
}

fn lookup_projection<'a>(
    docs: &'a sbproxy_modules::projections::ProjectionDocs,
    kind: &str,
    hostname: &str,
) -> Option<&'a bytes::Bytes> {
    match kind {
        "robots" => docs.robots_txt.get(hostname),
        "llms" => docs.llms_txt.get(hostname),
        "llms-full" => docs.llms_full_txt.get(hostname),
        "licenses" => docs.licenses_xml.get(hostname),
        "tdmrep" => docs.tdmrep_json.get(hostname),
        _ => None,
    }
}
