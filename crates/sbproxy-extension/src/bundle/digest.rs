//! Whole-bundle SHA-256 digest for `digest_scope: bundle_v1`.
//!
//! The original bundle digest covered the single file named by `entry`, which
//! left `bundle.yaml` unsigned. Hook kinds, sandbox limits, failure posture,
//! and `permissions` all live in that file, so the manifest that grants a
//! guest its capabilities was the one part of the bundle nothing verified.
//! This module closes that by hashing the manifest together with every other
//! shipped file.
//!
//! # The canonical index
//!
//! A `bundle_v1` digest is a hash of a text index rather than of concatenated
//! file bytes, so the format stays reproducible with ordinary command line
//! tools:
//!
//! ```text
//! sbproxy-bundle-digest/v1\n
//! <64 lowercase hex of file content><two spaces><path>\n
//! <64 lowercase hex of file content><two spaces><path>\n
//! ...
//! ```
//!
//! The bundle digest is the SHA-256 of those bytes. Each line carries its
//! file's path, so swapping two files' names changes the index even though the
//! set of content hashes did not move. The leading domain line keeps the index
//! from colliding with a plain `sha256sum` output file.
//!
//! # Rules
//!
//! * **Ordering.** Lines are sorted by the bundle-relative path, comparing
//!   UTF-8 bytes ascending. `bundle.yaml` takes its natural place in that
//!   order rather than a reserved slot.
//! * **Separator.** Path components join with `/` on every platform.
//! * **Coverage.** Every regular file in the bundle directory, recursively.
//!   Empty directories carry no content and are not represented.
//! * **Self-exclusion.** The `sha256` field cannot cover itself, so the
//!   manifest is hashed as its exact on-disk bytes with the single top-level
//!   `sha256:` line deleted, terminating newline included. Nothing else about
//!   the file is rewritten, normalized, or reordered.
//! * **File modes.** Not covered. Mode bits do not survive the transports a
//!   bundle travels through, and the host reads guest files into a sandbox
//!   rather than executing them from disk, so an executable bit grants a
//!   bundle nothing that the digest would be protecting.
//! * **Symlinks.** Refused, never followed. A symlink's bytes live outside
//!   the hashed content, and one pointing out of the bundle directory reads a
//!   file the operator never shipped.
//! * **Names.** A file name that has no single cross-platform form, or that
//!   carries a control character, refuses the bundle. A name holding a newline
//!   could otherwise forge an index line.
//!
//! Every failure here refuses the candidate. There is no warn-and-continue
//! path: an unverifiable bundle is not a degraded bundle.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read;

use cap_std::fs::{Dir, DirEntry};
use sha2::{Digest, Sha256};

use super::loader::{BundleLoadError, MAX_BUNDLE_ARTIFACT_BYTES};

/// First line of the canonical index, separating it from other digest formats.
const BUNDLE_DIGEST_DOMAIN: &str = "sbproxy-bundle-digest/v1\n";
/// Manifest file name, hashed from its canonical form rather than its bytes.
const MANIFEST_FILE_NAME: &str = "bundle.yaml";
/// Top-level manifest key removed before the manifest is hashed.
const DIGEST_KEY: &str = "sha256:";
/// Largest number of regular files one digested bundle may ship.
const MAX_BUNDLE_FILES: usize = 512;
/// Largest directory nesting depth walked inside one bundle.
const MAX_BUNDLE_DEPTH: usize = 8;
/// Largest total content one digested bundle may ship, in bytes.
const MAX_BUNDLE_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Largest single file the digest walk will read, in bytes.
const MAX_FILE_BYTES: u64 = MAX_BUNDLE_ARTIFACT_BYTES as u64;

/// Compute the `bundle_v1` digest of one open bundle directory.
///
/// `manifest_bytes` are the exact bytes read from `bundle.yaml`, and
/// `declared` is the `sha256` value parsed out of them.
pub(super) fn bundle_v1_digest(
    dir: &Dir,
    bundle_name: &str,
    manifest_bytes: &[u8],
    declared: &str,
) -> Result<String, BundleLoadError> {
    let canonical = canonical_manifest_bytes(bundle_name, manifest_bytes, declared)?;
    let mut entries = BTreeMap::new();
    entries.insert(
        MANIFEST_FILE_NAME.to_owned(),
        hex::encode(Sha256::digest(&canonical)),
    );

    let mut budget = MAX_BUNDLE_TOTAL_BYTES;
    collect(dir, "", 0, bundle_name, &mut entries, &mut budget)?;

    let mut index = String::from(BUNDLE_DIGEST_DOMAIN);
    for (path, content_digest) in &entries {
        index.push_str(content_digest);
        index.push_str("  ");
        index.push_str(path);
        index.push('\n');
    }
    Ok(hex::encode(Sha256::digest(index.as_bytes())))
}

/// Return the manifest bytes with the top-level `sha256:` line removed.
///
/// The removal is textual and exact so the same result is reachable with
/// `grep -v '^sha256:'`. Anything that makes the removal ambiguous refuses the
/// bundle instead of guessing: a manifest that is not UTF-8, one that does not
/// end in a newline, one where the key is not a plain top-level block key, or
/// one whose line does not hold the value the parser read.
fn canonical_manifest_bytes(
    bundle_name: &str,
    manifest_bytes: &[u8],
    declared: &str,
) -> Result<Vec<u8>, BundleLoadError> {
    let uncanonical = || {
        BundleLoadError::new(
            "digest",
            format!(
                "bundle `{bundle_name}` manifest cannot be canonicalized; \
                 digest_scope bundle_v1 needs a UTF-8 bundle.yaml that ends in a newline \
                 and writes sha256 as one unquoted top-level key with its value on the same line"
            ),
        )
    };

    let text = std::str::from_utf8(manifest_bytes).map_err(|_| uncanonical())?;
    if !text.ends_with('\n') {
        return Err(uncanonical());
    }

    let mut canonical = String::with_capacity(text.len());
    let mut removed = 0usize;
    for line in text.split_inclusive('\n') {
        let Some(value) = line.strip_prefix(DIGEST_KEY) else {
            canonical.push_str(line);
            continue;
        };
        removed += 1;
        let value = value
            .trim_matches(|character: char| character.is_ascii_whitespace())
            .trim_matches(|character: char| character == '\'' || character == '"');
        if value != declared {
            return Err(uncanonical());
        }
    }
    if removed != 1 {
        return Err(uncanonical());
    }
    Ok(canonical.into_bytes())
}

/// Walk one directory level, recording each regular file's content digest.
fn collect(
    dir: &Dir,
    prefix: &str,
    depth: usize,
    bundle_name: &str,
    entries: &mut BTreeMap<String, String>,
    budget: &mut u64,
) -> Result<(), BundleLoadError> {
    if depth > MAX_BUNDLE_DEPTH {
        return Err(BundleLoadError::new(
            "digest",
            format!("bundle `{bundle_name}` nests deeper than {MAX_BUNDLE_DEPTH} directories"),
        ));
    }

    let listing = dir.entries().map_err(|_| unreadable(bundle_name))?;
    for entry in listing {
        let entry = entry.map_err(|_| unreadable(bundle_name))?;
        let file_type = entry.file_type().map_err(|_| unreadable(bundle_name))?;
        if file_type.is_symlink() {
            return Err(BundleLoadError::new(
                "path",
                format!(
                    "bundle `{bundle_name}` contains a symlink; digest_scope bundle_v1 refuses \
                     symlinks because the bytes they name are outside the digest and may be \
                     outside the bundle directory"
                ),
            ));
        }

        let file_name = entry.file_name();
        let name = component(bundle_name, file_name.as_os_str())?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };

        if file_type.is_dir() {
            let child = entry.open_dir().map_err(|_| unreadable(bundle_name))?;
            collect(&child, &path, depth + 1, bundle_name, entries, budget)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(irregular(bundle_name));
        }
        if depth == 0 && path == MANIFEST_FILE_NAME {
            // Already recorded from its canonical form.
            continue;
        }
        if entries.len() >= MAX_BUNDLE_FILES {
            return Err(BundleLoadError::new(
                "digest",
                format!("bundle `{bundle_name}` ships more than {MAX_BUNDLE_FILES} files"),
            ));
        }

        let content_digest = hash_entry(&entry, bundle_name, budget)?;
        if entries.insert(path, content_digest).is_some() {
            return Err(BundleLoadError::new(
                "digest",
                format!("bundle `{bundle_name}` reaches one path through two directory entries"),
            ));
        }
    }
    Ok(())
}

/// Hash one regular file, charging its bytes against the bundle-wide budget.
fn hash_entry(
    entry: &DirEntry,
    bundle_name: &str,
    budget: &mut u64,
) -> Result<String, BundleLoadError> {
    let mut file = entry.open().map_err(|_| unreadable(bundle_name))?;
    let metadata = file.metadata().map_err(|_| unreadable(bundle_name))?;
    if !metadata.is_file() {
        return Err(irregular(bundle_name));
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| unreadable(bundle_name))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_FILE_BYTES {
            return Err(BundleLoadError::new(
                "digest",
                format!("bundle `{bundle_name}` ships a file larger than 16 MiB"),
            ));
        }
        if total > *budget {
            return Err(BundleLoadError::new(
                "digest",
                format!("bundle `{bundle_name}` ships more than 64 MiB of files"),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    *budget -= total;
    Ok(hex::encode(hasher.finalize()))
}

/// Validate one path component and return its canonical form.
fn component<'a>(bundle_name: &str, name: &'a OsStr) -> Result<&'a str, BundleLoadError> {
    let name = name.to_str().ok_or_else(|| uncanonical_name(bundle_name))?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return Err(uncanonical_name(bundle_name));
    }
    Ok(name)
}

fn uncanonical_name(bundle_name: &str) -> BundleLoadError {
    BundleLoadError::new(
        "path",
        format!(
            "bundle `{bundle_name}` ships a file name with no single canonical form; \
             names must be UTF-8 without control characters, `/`, or `\\`"
        ),
    )
}

fn unreadable(bundle_name: &str) -> BundleLoadError {
    BundleLoadError::new(
        "digest",
        format!("bundle `{bundle_name}` has a file the digest could not read"),
    )
}

fn irregular(bundle_name: &str) -> BundleLoadError {
    BundleLoadError::new(
        "digest",
        format!("bundle `{bundle_name}` ships an entry that is not a regular file or a directory"),
    )
}
