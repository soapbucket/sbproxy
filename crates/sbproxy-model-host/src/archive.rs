// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! In-process `.tar.gz` extraction for engine release archives.
//!
//! Model Host downloads llama.cpp / mistral.rs / uv as gzip tarballs and
//! used to shell out to the host `tar` binary so the lean crate could skip
//! an archive dependency. The public distroless image ships no `tar`, so
//! that extract never succeeds there (WOR-2412). Unpack in-process instead.

use std::io::Read;
use std::path::{Component, Path};

use flate2::read::GzDecoder;
use tar::Archive;

/// Extract a gzip-compressed tar archive into `dest`.
///
/// Refuses absolute paths and parent-directory components so a crafted
/// archive cannot write outside `dest`. Does not spawn `tar`.
pub fn extract_tar_gz(archive_path: &Path, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(archive_path)
        .map_err(|e| format!("open {}: {e}", archive_path.display()))?;
    extract_tar_gz_reader(file, dest).map_err(|e| {
        format!(
            "extract {} into {}: {e}",
            archive_path.display(),
            dest.display()
        )
    })
}

fn extract_tar_gz_reader<R: Read>(reader: R, dest: &Path) -> Result<(), String> {
    let decoder = GzDecoder::new(reader);
    let mut archive = Archive::new(decoder);
    archive.set_preserve_permissions(true);
    for entry in archive
        .entries()
        .map_err(|e| format!("read tar entries: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("read tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("tar entry path: {e}"))?
            .into_owned();
        if !is_safe_archive_path(&path) {
            return Err(format!(
                "refusing archive path that would escape the extract root: {}",
                path.display()
            ));
        }
        entry
            .unpack_in(dest)
            .map_err(|e| format!("unpack {}: {e}", path.display()))?;
    }
    Ok(())
}

fn is_safe_archive_path(path: &Path) -> bool {
    path.components().all(|component| match component {
        Component::Normal(_) | Component::CurDir => true,
        Component::Prefix(_) | Component::RootDir | Component::ParentDir => false,
    })
}

/// Blocking extract on the async runtime's blocking pool.
pub async fn extract_tar_gz_async(archive_path: &Path, dest: &Path) -> Result<(), String> {
    let archive_path = archive_path.to_path_buf();
    let dest = dest.to_path_buf();
    tokio::task::spawn_blocking(move || extract_tar_gz(&archive_path, &dest))
        .await
        .map_err(|e| format!("join tar extract: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, Header};

    fn write_tar_gz(path: &Path, files: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).expect("create archive");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        for (name, body) in files {
            let mut header = Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, name, *body)
                .expect("append tar entry");
        }
        builder.finish().expect("finish tar");
    }

    #[test]
    fn extracts_gzip_tarball_without_a_host_tar_binary() {
        let dir = tempfile::tempdir().expect("temp dir");
        let archive = dir.path().join("release.tar.gz");
        let dest = dir.path().join("staging");
        std::fs::create_dir(&dest).expect("staging");
        write_tar_gz(&archive, &[("bin/llama-server", b"fake-binary")]);

        extract_tar_gz(&archive, &dest).expect("extract");

        assert_eq!(
            std::fs::read(dest.join("bin/llama-server")).expect("read extracted"),
            b"fake-binary"
        );
    }

    #[test]
    fn archive_paths_must_stay_inside_the_extract_root() {
        assert!(is_safe_archive_path(Path::new("bin/llama-server")));
        assert!(is_safe_archive_path(Path::new("./mistralrs")));
        assert!(!is_safe_archive_path(Path::new("../escape")));
        assert!(!is_safe_archive_path(Path::new("/etc/passwd")));
        assert!(!is_safe_archive_path(Path::new("a/../../etc/passwd")));
    }

    #[tokio::test]
    async fn async_wrapper_extracts_on_the_blocking_pool() {
        let dir = tempfile::tempdir().expect("temp dir");
        let archive = dir.path().join("release.tar.gz");
        let dest = dir.path().join("staging");
        std::fs::create_dir(&dest).expect("staging");
        write_tar_gz(&archive, &[("mistralrs", b"fake-mistral")]);

        extract_tar_gz_async(&archive, &dest)
            .await
            .expect("async extract");
        assert_eq!(
            std::fs::read(dest.join("mistralrs")).expect("read extracted"),
            b"fake-mistral"
        );
    }
}
