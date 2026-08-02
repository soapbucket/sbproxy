// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Opaque process boundary used by every managed engine driver.

use std::collections::{BTreeMap, VecDeque};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::Read as _;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{EngineDriverError, EngineFailureReason};

const MAX_STDERR_TAIL_BYTES: usize = 64 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const PROCESS_OWNERSHIP_SCHEMA_VERSION: u32 = 1;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_PROCESS_OWNERSHIP_RECORD_BYTES: usize = 64 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_PROCESS_OWNERSHIP_RECORDS: usize = 4_096;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessIdentity {
    pid: u32,
    start_fingerprint: u64,
    executable: Option<PathBuf>,
}

/// Exact identity of the gateway process that owns one or more engines.
///
/// The start fingerprint prevents a later process that reuses the same PID
/// from authorizing engine cleanup. The executable is retained for audit
/// output but is not part of identity matching because binaries can be
/// replaced in place during an upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedEngineOwner {
    pid: u32,
    start_fingerprint: u64,
    executable: Option<PathBuf>,
}

impl ManagedEngineOwner {
    /// Whether two tokens identify the same process generation.
    ///
    /// The executable path is audit context only. It can change its rendered
    /// form when an installed binary is replaced while the process is alive.
    pub fn same_process_generation(&self, other: &Self) -> bool {
        self.pid == other.pid && self.start_fingerprint == other.start_fingerprint
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedProcessOwnership {
    schema_version: u32,
    owner: ProcessIdentity,
    engine: ProcessIdentity,
    process_group: u32,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct ProcessOwnershipStore {
    directory: PathBuf,
    #[cfg(test)]
    fail_persist: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct OwnershipDirectory {
    path: PathBuf,
    file: std::fs::File,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ProcessOwnershipStore {
    fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            #[cfg(test)]
            fail_persist: false,
        }
    }

    #[cfg(test)]
    fn failing_at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            fail_persist: true,
        }
    }

    fn production() -> Self {
        #[cfg(test)]
        {
            Self::at(std::env::temp_dir().join(format!(
                "sbproxy-managed-engine-tests-{}",
                std::process::id()
            )))
        }
        #[cfg(not(test))]
        if let Some(path) =
            std::env::var_os("SBPROXY_ENGINE_OWNERSHIP_DIR").filter(|path| !path.is_empty())
        {
            return Self::at(path);
        }
        #[cfg(all(not(test), target_os = "macos"))]
        if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
            return Self::at(
                PathBuf::from(home).join("Library/Application Support/sbproxy/managed-engines"),
            );
        }
        #[cfg(all(not(test), target_os = "linux"))]
        {
            if let Some(state) =
                std::env::var_os("XDG_STATE_HOME").filter(|state| !state.is_empty())
            {
                return Self::at(PathBuf::from(state).join("sbproxy/managed-engines"));
            }
            if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
                return Self::at(PathBuf::from(home).join(".local/state/sbproxy/managed-engines"));
            }
        }
        #[cfg(not(test))]
        {
            // A missing home/state environment is unusual for a service, but
            // it must not disable exact ownership. Scope the fallback by
            // effective user so two accounts never share records.
            // SAFETY: geteuid takes no arguments and has no preconditions.
            let uid = unsafe { libc::geteuid() };
            Self::at(std::env::temp_dir().join(format!("sbproxy-managed-engines-{uid}")))
        }
    }

    #[cfg(test)]
    fn persist(
        &self,
        record: ManagedProcessOwnership,
    ) -> Result<StoredProcessOwnership, EngineDriverError> {
        let directory = self.open_or_create()?;
        self.persist_in(directory, record)
    }

    fn persist_in(
        &self,
        directory: Arc<OwnershipDirectory>,
        record: ManagedProcessOwnership,
    ) -> Result<StoredProcessOwnership, EngineDriverError> {
        if record.schema_version != PROCESS_OWNERSHIP_SCHEMA_VERSION
            || record.engine.pid == 0
            || record.process_group != record.engine.pid
        {
            return Err(process_ownership_error(
                "persist managed-engine ownership",
                "record identity or process group is invalid",
            ));
        }
        #[cfg(test)]
        if self.fail_persist {
            return Err(process_ownership_error(
                "persist managed-engine ownership",
                "injected durable-write failure",
            ));
        }
        let name = OsString::from(format!(
            "{}-{}.json",
            record.engine.pid, record.engine.start_fingerprint
        ));
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = OsString::from(format!(
            ".{}-{}-{nonce}.tmp",
            record.engine.pid,
            std::process::id()
        ));
        let bytes = serde_json::to_vec_pretty(&record).map_err(|error| {
            process_ownership_error("encode managed-engine ownership", error.to_string())
        })?;
        let mut file = directory.create_record(&temporary)?;
        let write_result = (|| -> std::io::Result<()> {
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            directory.rename(&temporary, &name)?;
            directory.sync()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = directory.unlink(&temporary);
            return Err(process_ownership_error(
                "atomically persist managed-engine ownership",
                error.to_string(),
            ));
        }
        Ok(StoredProcessOwnership {
            directory,
            name,
            record,
        })
    }

    #[cfg(test)]
    fn ensure_private_directory(&self) -> Result<(), EngineDriverError> {
        self.open_or_create()?;
        Ok(())
    }

    #[cfg(test)]
    fn record_paths(&self) -> Result<Vec<PathBuf>, EngineDriverError> {
        let Some(directory) = self.open_existing()? else {
            return Ok(Vec::new());
        };
        Ok(directory
            .record_names()?
            .into_iter()
            .map(|name| directory.path.join(name))
            .collect())
    }

    fn records(&self) -> Result<Vec<StoredProcessOwnership>, EngineDriverError> {
        let Some(directory) = self.open_existing()? else {
            return Ok(Vec::new());
        };
        directory
            .record_names()?
            .into_iter()
            .map(|name| {
                let record = directory.read_record(&name)?;
                Ok(StoredProcessOwnership {
                    directory: Arc::clone(&directory),
                    name,
                    record,
                })
            })
            .collect()
    }

    fn open_existing(&self) -> Result<Option<Arc<OwnershipDirectory>>, EngineDriverError> {
        OwnershipDirectory::open(&self.directory, false).map(|directory| directory.map(Arc::new))
    }

    fn open_or_create(&self) -> Result<Arc<OwnershipDirectory>, EngineDriverError> {
        OwnershipDirectory::open(&self.directory, true)?
            .map(Arc::new)
            .ok_or_else(|| {
                process_ownership_error(
                    "create managed-engine ownership directory",
                    "directory remained absent after creation",
                )
            })
    }

    fn reap_stale(&self, grace: Duration) -> Result<usize, EngineDriverError> {
        let mut reaped = 0;
        for ownership in self.records()? {
            let record = &ownership.record;
            if process_identity(record.owner.pid)
                .as_ref()
                .is_some_and(|actual| identity_matches(&record.owner, actual))
            {
                continue;
            }
            reaped += usize::from(reap_stored_ownership(&ownership, grace)?);
        }
        Ok(reaped)
    }

    fn reap_owned_by(
        &self,
        owner_pid: u32,
        owner_exit_timeout: Duration,
        engine_grace: Duration,
    ) -> Result<usize, EngineDriverError> {
        let records = self.records()?;
        let mut owners = records
            .iter()
            .filter(|ownership| ownership.record.owner.pid == owner_pid)
            .map(|ownership| ownership.record.owner.clone())
            .collect::<Vec<_>>();
        owners.sort_by_key(|owner| owner.start_fingerprint);
        owners.dedup_by_key(|owner| owner.start_fingerprint);
        if owners.len() > 1 {
            return Err(process_ownership_error(
                format!("resolve managed-engine owner pid {owner_pid}"),
                "multiple recorded process generations use this PID; retry with an exact owner token",
            ));
        }
        let Some(owner) = owners.into_iter().next() else {
            return Ok(0);
        };
        self.reap_owned_by_identity(
            &ManagedEngineOwner::from(owner),
            owner_exit_timeout,
            engine_grace,
        )
    }

    fn reap_owned_by_identity(
        &self,
        owner: &ManagedEngineOwner,
        owner_exit_timeout: Duration,
        engine_grace: Duration,
    ) -> Result<usize, EngineDriverError> {
        let owner_identity = owner.identity();
        if !wait_for_identity_change(&owner_identity, owner_exit_timeout) {
            return Err(process_ownership_error(
                format!("wait for managed-engine owner pid {}", owner.pid),
                "owner retained its recorded start fingerprint after service unload",
            ));
        }
        let mut reaped = 0;
        for ownership in self
            .records()?
            .into_iter()
            .filter(|ownership| identity_matches(&owner_identity, &ownership.record.owner))
        {
            reaped += usize::from(reap_stored_ownership(&ownership, engine_grace)?);
        }
        Ok(reaped)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ManagedEngineOwner {
    fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            start_fingerprint: self.start_fingerprint,
            executable: self.executable.clone(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl From<ProcessIdentity> for ManagedEngineOwner {
    fn from(identity: ProcessIdentity) -> Self {
        Self {
            pid: identity.pid,
            start_fingerprint: identity.start_fingerprint,
            executable: identity.executable,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl OwnershipDirectory {
    fn open(path: &Path, create: bool) -> Result<Option<Self>, EngineDriverError> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;

        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| {
                    process_ownership_error(
                        "resolve managed-engine ownership directory",
                        error.to_string(),
                    )
                })?
                .join(path)
        };
        #[cfg(target_os = "macos")]
        let path = normalize_macos_root_alias(path);
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => {}
                std::path::Component::Normal(name) => components.push(name.to_os_string()),
                std::path::Component::ParentDir => {
                    return Err(process_ownership_error(
                        "validate managed-engine ownership directory",
                        format!("'{}' contains a parent-directory component", path.display()),
                    ));
                }
                std::path::Component::Prefix(_) => {
                    return Err(process_ownership_error(
                        "validate managed-engine ownership directory",
                        format!("'{}' has an unsupported path prefix", path.display()),
                    ));
                }
            }
        }
        let name = components.pop().ok_or_else(|| {
            process_ownership_error(
                "validate managed-engine ownership directory",
                format!(
                    "'{}' cannot be used as a private state directory",
                    path.display()
                ),
            )
        })?;
        let root = CString::new("/").expect("root path contains no NUL");
        let descriptor = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(process_ownership_error(
                "open managed-engine ownership path root",
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let mut parent_file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        let mut parent_path = PathBuf::from("/");

        for component in components {
            validate_ownership_parent(&parent_file, &parent_path)?;
            let component_c = CString::new(component.as_bytes()).map_err(|_| {
                process_ownership_error(
                    "open managed-engine ownership ancestor directory",
                    "path contains a NUL byte",
                )
            })?;
            let mut descriptor = unsafe {
                libc::openat(
                    parent_file.as_raw_fd(),
                    component_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if descriptor < 0 {
                let error = std::io::Error::last_os_error();
                if !create && error.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
                if !create || error.kind() != std::io::ErrorKind::NotFound {
                    return Err(process_ownership_error(
                        "open managed-engine ownership ancestor directory",
                        format!("'{}': {error}", parent_path.join(&component).display()),
                    ));
                }
                if unsafe { libc::mkdirat(parent_file.as_raw_fd(), component_c.as_ptr(), 0o700) }
                    != 0
                {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(process_ownership_error(
                            "create managed-engine ownership ancestor directory",
                            format!("'{}': {error}", parent_path.join(&component).display()),
                        ));
                    }
                } else {
                    parent_file.sync_all().map_err(|error| {
                        process_ownership_error(
                            "sync managed-engine ownership ancestor directory",
                            error.to_string(),
                        )
                    })?;
                }
                descriptor = unsafe {
                    libc::openat(
                        parent_file.as_raw_fd(),
                        component_c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    )
                };
                if descriptor < 0 {
                    return Err(process_ownership_error(
                        "open created managed-engine ownership ancestor directory",
                        format!(
                            "'{}': {}",
                            parent_path.join(&component).display(),
                            std::io::Error::last_os_error()
                        ),
                    ));
                }
            }
            parent_file = unsafe { std::fs::File::from_raw_fd(descriptor) };
            parent_path.push(component);
        }
        validate_ownership_parent(&parent_file, &parent_path)?;

        let name_c = CString::new(name.as_bytes()).map_err(|_| {
            process_ownership_error(
                "open managed-engine ownership directory",
                "directory name contains a NUL byte",
            )
        })?;
        if create {
            let result = unsafe { libc::mkdirat(parent_file.as_raw_fd(), name_c.as_ptr(), 0o700) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(process_ownership_error(
                        "create managed-engine ownership directory",
                        error.to_string(),
                    ));
                }
            } else {
                parent_file.sync_all().map_err(|error| {
                    process_ownership_error(
                        "sync managed-engine ownership parent directory",
                        error.to_string(),
                    )
                })?;
            }
        }
        let descriptor = unsafe {
            libc::openat(
                parent_file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            if !create && error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(process_ownership_error(
                "open managed-engine ownership directory",
                error.to_string(),
            ));
        }
        let directory = Self {
            path,
            file: unsafe { std::fs::File::from_raw_fd(descriptor) },
        };
        directory.validate()?;
        Ok(Some(directory))
    }

    fn validate(&self) -> Result<(), EngineDriverError> {
        use std::os::fd::AsRawFd as _;

        let metadata = descriptor_stat(self.file.as_raw_fd()).map_err(|error| {
            process_ownership_error(
                "inspect managed-engine ownership directory",
                error.to_string(),
            )
        })?;
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.st_uid != effective_uid {
            return Err(process_ownership_error(
                "validate managed-engine ownership directory",
                format!(
                    "'{}' is owned by uid {}, expected effective uid {effective_uid}",
                    self.path.display(),
                    metadata.st_uid
                ),
            ));
        }
        // Tighten a legacy owner-only mode on every open, not just when the
        // directory is being created. Pre-hardening binaries created this
        // directory 0755, so gating the repair on the create path turns the
        // first boot after an upgrade into a hard failure (WOR-2167). Group-
        // or world-writable stays a hard error below: that is a tamper risk,
        // not a legacy artifact.
        let mut mode = metadata.st_mode & 0o777;
        if mode != 0o700 && mode & 0o022 == 0 {
            if unsafe { libc::fchmod(self.file.as_raw_fd(), 0o700) } != 0 {
                return Err(process_ownership_error(
                    "tighten managed-engine ownership directory",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            mode = 0o700;
        }
        if mode != 0o700 {
            return Err(process_ownership_error(
                "validate managed-engine ownership directory",
                format!(
                    "'{}' has mode {mode:04o}, expected 0700",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    fn create_record(&self, name: &OsStr) -> Result<std::fs::File, EngineDriverError> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let name = record_name_cstring(name)?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(process_ownership_error(
                "create managed-engine ownership record",
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
    }

    fn read_record(&self, name: &OsStr) -> Result<ManagedProcessOwnership, EngineDriverError> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let name_c = record_name_cstring(name)?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(process_ownership_error(
                format!(
                    "read managed-engine ownership '{}'",
                    self.path.join(name).display()
                ),
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        let metadata = descriptor_stat(file.as_raw_fd()).map_err(|error| {
            process_ownership_error(
                format!(
                    "inspect managed-engine ownership '{}'",
                    self.path.join(name).display()
                ),
                error.to_string(),
            )
        })?;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_uid != unsafe { libc::geteuid() }
            || metadata.st_mode & 0o022 != 0
        {
            return Err(process_ownership_error(
                format!(
                    "validate managed-engine ownership '{}'",
                    self.path.join(name).display()
                ),
                "record is not a private regular file owned by the effective user",
            ));
        }
        if metadata.st_size < 0
            || u64::try_from(metadata.st_size).unwrap_or(u64::MAX)
                > MAX_PROCESS_OWNERSHIP_RECORD_BYTES as u64
        {
            return Err(process_ownership_error(
                format!(
                    "validate managed-engine ownership '{}'",
                    self.path.join(name).display()
                ),
                format!(
                    "record exceeds the {}-byte size limit",
                    MAX_PROCESS_OWNERSHIP_RECORD_BYTES
                ),
            ));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take((MAX_PROCESS_OWNERSHIP_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                process_ownership_error(
                    format!(
                        "read managed-engine ownership '{}'",
                        self.path.join(name).display()
                    ),
                    error.to_string(),
                )
            })?;
        if bytes.len() > MAX_PROCESS_OWNERSHIP_RECORD_BYTES {
            return Err(process_ownership_error(
                format!(
                    "validate managed-engine ownership '{}'",
                    self.path.join(name).display()
                ),
                format!(
                    "record exceeds the {}-byte size limit",
                    MAX_PROCESS_OWNERSHIP_RECORD_BYTES
                ),
            ));
        }
        validate_ownership_record(&self.path.join(name), &bytes)
    }

    fn record_names(&self) -> Result<Vec<OsString>, EngineDriverError> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStringExt as _;

        let duplicate = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(process_ownership_error(
                "duplicate managed-engine ownership directory",
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(duplicate);
            }
            return Err(process_ownership_error(
                "read managed-engine ownership directory",
                error.to_string(),
            ));
        }
        let stream = DirectoryStream(stream);
        let mut names = Vec::new();
        loop {
            clear_errno();
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error().unwrap_or_default() == 0 {
                    break;
                }
                return Err(process_ownership_error(
                    "read managed-engine ownership directory",
                    error.to_string(),
                ));
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." || !bytes.ends_with(b".json") {
                continue;
            }
            push_bounded_record_name(&mut names, OsString::from_vec(bytes.to_vec()))?;
        }
        names.sort();
        Ok(names)
    }

    fn rename(&self, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;

        let from = record_name_io_cstring(from)?;
        let to = record_name_io_cstring(to)?;
        if unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                from.as_ptr(),
                self.file.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn unlink(&self, name: &OsStr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;

        let name = record_name_io_cstring(name)?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error);
            }
        }
        Ok(())
    }

    fn clear(&self, name: &OsStr) -> Result<(), EngineDriverError> {
        self.unlink(name).map_err(|error| {
            process_ownership_error(
                format!(
                    "remove managed-engine ownership '{}'",
                    self.path.join(name).display()
                ),
                error.to_string(),
            )
        })?;
        self.sync().map_err(|error| {
            process_ownership_error("sync managed-engine ownership directory", error.to_string())
        })
    }

    fn sync(&self) -> std::io::Result<()> {
        self.file.sync_all()
    }

    #[cfg(target_os = "macos")]
    fn create_cloexec_fifo_pair(
        &self,
        label: &str,
    ) -> std::io::Result<(std::fs::File, std::fs::File)> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        static NEXT_GATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let mut selected = None;
        for _ in 0..32 {
            let sequence = NEXT_GATE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let name = OsString::from(format!(
                ".gate-{label}-{}-{sequence}.fifo",
                std::process::id()
            ));
            let name_c = record_name_io_cstring(&name)?;
            if unsafe { libc::mkfifoat(self.file.as_raw_fd(), name_c.as_ptr(), 0o600) } == 0 {
                selected = Some((name, name_c));
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        let (name, name_c) = selected.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate a unique managed-engine gate FIFO",
            )
        })?;
        let reader = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if reader < 0 {
            let error = std::io::Error::last_os_error();
            let _ = self.unlink(&name);
            return Err(error);
        }
        let reader = unsafe { std::fs::File::from_raw_fd(reader) };
        let writer = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if writer < 0 {
            let error = std::io::Error::last_os_error();
            let _ = self.unlink(&name);
            return Err(error);
        }
        let writer = unsafe { std::fs::File::from_raw_fd(writer) };
        self.unlink(&name)?;
        set_file_blocking(reader.as_raw_fd())?;
        set_file_blocking(writer.as_raw_fd())?;
        Ok((reader, writer))
    }
}

#[cfg(target_os = "macos")]
fn set_file_blocking(descriptor: libc::c_int) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn normalize_macos_root_alias(path: PathBuf) -> PathBuf {
    // macOS installs these root entries as root-owned aliases into /private.
    // Resolve only those fixed operating-system aliases before the fd-relative
    // walk; arbitrary user-selected symlinks remain rejected at every level.
    for (alias, target) in [
        (Path::new("/var"), Path::new("/private/var")),
        (Path::new("/tmp"), Path::new("/private/tmp")),
        (Path::new("/etc"), Path::new("/private/etc")),
    ] {
        if let Ok(suffix) = path.strip_prefix(alias) {
            return target.join(suffix);
        }
    }
    path
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn push_bounded_record_name(
    names: &mut Vec<OsString>,
    name: OsString,
) -> Result<(), EngineDriverError> {
    if names.len() >= MAX_PROCESS_OWNERSHIP_RECORDS {
        return Err(process_ownership_error(
            "read managed-engine ownership directory",
            format!(
                "record limit of {} was exceeded",
                MAX_PROCESS_OWNERSHIP_RECORDS
            ),
        ));
    }
    names.push(name);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_ownership_parent(parent: &std::fs::File, path: &Path) -> Result<(), EngineDriverError> {
    use std::os::fd::AsRawFd as _;

    let metadata = descriptor_stat(parent.as_raw_fd()).map_err(|error| {
        process_ownership_error(
            "inspect managed-engine ownership parent directory",
            error.to_string(),
        )
    })?;
    let mode = metadata.st_mode;
    if mode & libc::S_IFMT != libc::S_IFDIR || (mode & 0o022 != 0 && mode & libc::S_ISVTX == 0) {
        return Err(process_ownership_error(
            "validate managed-engine ownership directory",
            format!(
                "parent '{}' is not a directory or is writable by other users without the sticky bit",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn descriptor_stat(descriptor: libc::c_int) -> std::io::Result<libc::stat> {
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(descriptor, &mut metadata) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(metadata)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn record_name_cstring(name: &OsStr) -> Result<CString, EngineDriverError> {
    record_name_io_cstring(name).map_err(|error| {
        process_ownership_error(
            "validate managed-engine ownership record name",
            error.to_string(),
        )
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn record_name_io_cstring(name: &OsStr) -> std::io::Result<CString> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "record name is not a single path component",
        ));
    }
    CString::new(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "record name contains a NUL byte",
        )
    })
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    unsafe {
        *libc::__errno_location() = 0;
    }
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe {
        *libc::__error() = 0;
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct DirectoryStream(*mut libc::DIR);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct StoredProcessOwnership {
    directory: Arc<OwnershipDirectory>,
    name: OsString,
    record: ManagedProcessOwnership,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl StoredProcessOwnership {
    fn clear(&self) -> Result<(), EngineDriverError> {
        self.directory.clear(&self.name)
    }

    fn clear_after_verified_exit(&self) -> Result<(), EngineDriverError> {
        if process_identity(self.record.engine.pid)
            .as_ref()
            .is_some_and(|actual| identity_matches(&self.record.engine, actual))
            || process_group_exists(self.record.process_group)
        {
            return Err(process_ownership_error(
                format!(
                    "clear managed-engine ownership process group {}",
                    self.record.process_group
                ),
                "the exact process or one of its process-group descendants is still alive",
            ));
        }
        self.clear()
    }

    fn exact_engine_is_current(&self) -> bool {
        process_identity(self.record.engine.pid)
            .as_ref()
            .is_some_and(|actual| identity_matches(&self.record.engine, actual))
    }

    fn exact_engine_owns_recorded_group(&self) -> bool {
        self.exact_engine_is_current()
            && process_group_for(self.record.engine.pid) == Some(self.record.process_group)
    }

    fn signal_group_if_exact(&self, signal: i32) -> Result<(), EngineDriverError> {
        if self.exact_engine_owns_recorded_group() {
            signal_isolated_process_group(self.record.process_group, signal);
            return Ok(());
        }
        if !process_group_exists(self.record.process_group) {
            return Ok(());
        }
        Err(process_ownership_error(
            format!(
                "signal managed engine process group {}",
                self.record.process_group
            ),
            "cannot prove the occupied process group still belongs to the exact recorded engine; ownership was retained",
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reap_stored_ownership(
    ownership: &StoredProcessOwnership,
    grace: Duration,
) -> Result<bool, EngineDriverError> {
    let record = &ownership.record;
    match process_identity(record.engine.pid) {
        Some(actual_engine)
            if identity_matches(&record.engine, &actual_engine)
                && process_group_for(record.engine.pid) == Some(record.process_group) => {}
        Some(actual_engine) if identity_matches(&record.engine, &actual_engine) => {
            return Err(process_ownership_error(
                format!(
                    "reap managed engine process group {}",
                    record.process_group
                ),
                "the exact recorded engine no longer owns its recorded process group; ownership was retained",
            ));
        }
        Some(_) | None if !process_group_exists(record.process_group) => {
            ownership.clear()?;
            return Ok(false);
        }
        Some(_) | None => {
            return Err(process_ownership_error(
                format!(
                    "reap managed engine process group {}",
                    record.process_group
                ),
                "cannot prove the occupied process group still belongs to the exact recorded engine; ownership was retained for an operator to resolve",
            ));
        }
    }

    signal_isolated_process_group(record.process_group, libc::SIGTERM);
    if !wait_for_process_group_exit(record.process_group, grace) {
        if process_identity(record.engine.pid)
            .as_ref()
            .is_none_or(|actual| !identity_matches(&record.engine, actual))
            || process_group_for(record.engine.pid) != Some(record.process_group)
        {
            return Err(process_ownership_error(
                format!(
                    "force-stop managed engine process group {}",
                    record.process_group
                ),
                "cannot prove the occupied process group still belongs to the exact recorded engine after its graceful-stop window; ownership was retained",
            ));
        }
        signal_isolated_process_group(record.process_group, libc::SIGKILL);
        if !wait_for_process_group_exit(record.process_group, Duration::from_secs(5)) {
            return Err(process_ownership_error(
                format!("reap managed engine process group {}", record.process_group),
                "exact process group remained alive after SIGKILL",
            ));
        }
    }
    ownership.clear()?;
    Ok(true)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn identity_matches(expected: &ProcessIdentity, actual: &ProcessIdentity) -> bool {
    expected.pid == actual.pid && expected.start_fingerprint == actual.start_fingerprint
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wait_for_identity_change(identity: &ProcessIdentity, duration: Duration) -> bool {
    let deadline = std::time::Instant::now() + duration;
    loop {
        if process_identity(identity.pid)
            .as_ref()
            .is_none_or(|actual| !identity_matches(identity, actual))
        {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn wait_for_process_group_exit(process_group: u32, duration: Duration) -> bool {
    let deadline = std::time::Instant::now() + duration;
    loop {
        reap_exited_children_in_group(process_group);
        if !process_group_exists(process_group) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn reap_exited_children_in_group(process_group: u32) {
    let process_group = process_group as libc::pid_t;
    if process_group <= 0 {
        return;
    }
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(-process_group, &mut status, libc::WNOHANG) };
        if waited > 0 {
            continue;
        }
        if waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return;
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_ownership_record(
    path: &Path,
    bytes: &[u8],
) -> Result<ManagedProcessOwnership, EngineDriverError> {
    let record: ManagedProcessOwnership = serde_json::from_slice(bytes).map_err(|error| {
        process_ownership_error(
            format!("parse managed-engine ownership '{}'", path.display()),
            error.to_string(),
        )
    })?;
    if record.schema_version != PROCESS_OWNERSHIP_SCHEMA_VERSION
        || record.engine.pid == 0
        || record.process_group != record.engine.pid
    {
        return Err(process_ownership_error(
            format!("validate managed-engine ownership '{}'", path.display()),
            "unsupported schema or unsafe process group",
        ));
    }
    Ok(record)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn process_ownership_error(
    action: impl std::fmt::Display,
    detail: impl std::fmt::Display,
) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineShutdownFailed,
        format!("{action}: {detail}"),
        "inspect the managed-engine ownership directory and retry",
        true,
    )
}

/// Reap only engines whose durable owner identity is no longer alive.
///
/// PID reuse is guarded by the recorded process-start fingerprint; executable
/// identity is retained as audit evidence. This function never scans or
/// signals by process name.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn reap_stale_managed_engines(grace: Duration) -> Result<usize, EngineDriverError> {
    ProcessOwnershipStore::production().reap_stale(grace)
}

/// Capture the exact process generation for a managed-engine owner.
///
/// Call this before asking a service manager to stop the owner, then persist
/// the returned token if cleanup may need to be retried after the PID exits.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn capture_managed_engine_owner(pid: u32) -> Option<ManagedEngineOwner> {
    process_identity(pid).map(ManagedEngineOwner::from)
}

/// Reap only records belonging to one exact owner from an explicit store.
///
/// An explicit directory lets service management honor the environment
/// loaded by the service itself instead of accidentally consulting the
/// caller's shell.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn reap_managed_engines_owned_by_identity_at(
    directory: &Path,
    owner: &ManagedEngineOwner,
    owner_exit_timeout: Duration,
    engine_grace: Duration,
) -> Result<usize, EngineDriverError> {
    ProcessOwnershipStore::at(directory).reap_owned_by_identity(
        owner,
        owner_exit_timeout,
        engine_grace,
    )
}

/// Wait for one exact recorded owner to exit, then reap its exact engines.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn reap_managed_engines_owned_by(
    owner_pid: u32,
    owner_exit_timeout: Duration,
    engine_grace: Duration,
) -> Result<usize, EngineDriverError> {
    ProcessOwnershipStore::production().reap_owned_by(owner_pid, owner_exit_timeout, engine_grace)
}

/// Platforms without exact process-start fingerprints retain their native
/// process handle and do not perform durable stale-process recovery.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn reap_stale_managed_engines(_grace: Duration) -> Result<usize, EngineDriverError> {
    Ok(0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
/// Exact owner capture is unavailable without a process-start fingerprint.
pub fn capture_managed_engine_owner(_pid: u32) -> Option<ManagedEngineOwner> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
/// Durable exact-owner recovery is unavailable on this platform.
pub fn reap_managed_engines_owned_by_identity_at(
    _directory: &Path,
    _owner: &ManagedEngineOwner,
    _owner_exit_timeout: Duration,
    _engine_grace: Duration,
) -> Result<usize, EngineDriverError> {
    Ok(0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn reap_managed_engines_owned_by(
    _owner_pid: u32,
    _owner_exit_timeout: Duration,
    _engine_grace: Duration,
) -> Result<usize, EngineDriverError> {
    Ok(0)
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> Option<ProcessIdentity> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.rsplit_once(") ")?.1;
    let fields = after_name.split_whitespace().collect::<Vec<_>>();
    if fields.first().copied() == Some("Z") {
        return None;
    }
    let start_fingerprint = fields.get(19)?.parse().ok()?;
    Some(ProcessIdentity {
        pid,
        start_fingerprint,
        executable: std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
    })
}

#[cfg(target_os = "macos")]
fn process_identity(pid: u32) -> Option<ProcessIdentity> {
    use std::os::unix::ffi::OsStringExt as _;

    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    const SZOMB: u32 = 5;

    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; 16],
        pbi_name: [u8; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    #[link(name = "proc")]
    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;
        fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
    }

    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
    let expected = std::mem::size_of::<ProcBsdInfo>();
    let read = unsafe {
        proc_pidinfo(
            i32::try_from(pid).ok()?,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(expected).ok()?,
        )
    };
    if usize::try_from(read).ok()? != expected {
        return None;
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_status == SZOMB {
        return None;
    }
    let mut path_buffer = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
    let path_length = unsafe {
        proc_pidpath(
            i32::try_from(pid).ok()?,
            path_buffer.as_mut_ptr().cast(),
            u32::try_from(path_buffer.len()).ok()?,
        )
    };
    let executable = usize::try_from(path_length)
        .ok()
        .filter(|length| *length > 0 && *length <= path_buffer.len())
        .map(|length| {
            path_buffer.truncate(length);
            PathBuf::from(std::ffi::OsString::from_vec(path_buffer))
        });
    Some(ProcessIdentity {
        pid,
        start_fingerprint: info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
        executable,
    })
}

/// Process operations available to engine drivers after a typed spawn.
#[async_trait]
pub trait EngineProcess: std::fmt::Debug + Send + Sync {
    /// Operating-system process ID, when the engine is a subprocess.
    fn id(&self) -> Option<u32>;

    /// Whether the engine process has already exited.
    async fn has_exited(&self) -> Result<bool, EngineDriverError>;

    /// Request graceful shutdown, then force termination after `grace`.
    async fn shutdown(&self, grace: Duration) -> Result<(), EngineDriverError>;

    /// Bounded, operator-safe stderr tail captured for diagnostics.
    fn stderr_tail(&self) -> String;
}

/// Exact tokenized command accepted by the managed process boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineCommand {
    /// Executable selected by a managed driver.
    pub executable: PathBuf,
    /// Already-tokenized argument vector. No shell parsing occurs.
    pub arguments: Vec<String>,
    /// Explicit environment overrides.
    pub environment: BTreeMap<String, String>,
    /// Allocated loopback port.
    pub port: u16,
    /// HTTP readiness path.
    pub health_path: String,
    /// Maximum duration to wait for readiness.
    pub ready_timeout: Duration,
    /// Maximum nonempty stderr lines retained in diagnostics.
    pub stderr_tail_lines: usize,
}

/// Side-effecting command executor. Implementations receive tokens, never a shell string.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Spawn one executable with exact argv and environment overrides.
    async fn spawn(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError>;

    /// Run one fixed command to completion with bounded output and timeout.
    async fn output(
        &self,
        _executable: &Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _timeout: Duration,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        Err(EngineDriverError::blocked(
            "bounded command output is unavailable from this executor",
            "configure a command executor that supports compatibility probes",
        ))
    }
}

/// Bounded output from one fixed, shell-free compatibility command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Whether the process exited successfully.
    pub success: bool,
    /// Redacted and size-bounded standard output.
    pub stdout: String,
    /// Redacted and size-bounded standard error.
    pub stderr: String,
}

/// Readiness probe injected into the process runner for deterministic tests.
#[async_trait]
pub trait EngineReadinessProbe: Send + Sync {
    /// Return whether the loopback health endpoint is ready.
    async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError>;
}

/// Shared process spawn, early-exit, readiness, and shutdown boundary.
#[derive(Clone)]
pub struct EngineProcessRunner {
    executor: Arc<dyn CommandExecutor>,
    probe: Arc<dyn EngineReadinessProbe>,
    poll_interval: Duration,
}

impl std::fmt::Debug for EngineProcessRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineProcessRunner")
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

impl EngineProcessRunner {
    /// Construct a runner from explicit command and health adapters.
    pub fn new(executor: Arc<dyn CommandExecutor>, probe: Arc<dyn EngineReadinessProbe>) -> Self {
        Self {
            executor,
            probe,
            poll_interval: Duration::from_millis(100),
        }
    }

    /// Override the readiness poll interval.
    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval.max(Duration::from_millis(1));
        self
    }

    /// Spawn one typed command and wait until ready, exited, or timed out.
    pub async fn launch(
        &self,
        command: &EngineCommand,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        validate_command(command)?;
        let process = self
            .executor
            .spawn(
                &command.executable,
                &command.arguments,
                &command.environment,
                command.stderr_tail_lines,
            )
            .await?;
        let deadline = tokio::time::Instant::now() + command.ready_timeout;
        loop {
            if process.has_exited().await? {
                let tail = process.stderr_tail();
                let error = EngineDriverError::new(
                    EngineFailureReason::EngineEarlyExit,
                    format!("engine {:?} exited before readiness", command.executable),
                    "inspect the bounded stderr tail, correct engine compatibility, and retry",
                    true,
                );
                return Err(if tail.is_empty() {
                    error
                } else {
                    error.with_diagnostic_tail(tail)
                });
            }
            if self.probe.ready(command.port, &command.health_path).await? {
                return Ok(process);
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = process.shutdown(Duration::from_secs(1)).await;
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineReadinessTimeout,
                    format!(
                        "engine {:?} was not ready within {:?}",
                        command.executable, command.ready_timeout
                    ),
                    "inspect engine health and resource fit, then increase the typed readiness deadline only if startup is expected to take longer",
                    true,
                ));
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// Perform one readiness probe through the injected health boundary.
    pub async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError> {
        self.probe.ready(port, path).await
    }

    /// Run one fixed compatibility command through the shared command boundary.
    pub async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        self.executor
            .output(
                executable,
                arguments,
                environment,
                timeout,
                max_output_bytes,
            )
            .await
    }
}

impl Default for EngineProcessRunner {
    fn default() -> Self {
        Self::new(
            Arc::new(TokioCommandExecutor),
            Arc::new(LoopbackReadinessProbe),
        )
    }
}

fn validate_command(command: &EngineCommand) -> Result<(), EngineDriverError> {
    if command.executable.as_os_str().is_empty() {
        return Err(EngineDriverError::new(
            EngineFailureReason::EngineSpawnFailed,
            "engine executable must not be empty",
            "select a detected or provisioned engine executable",
            false,
        ));
    }
    if command.port == 0 || command.ready_timeout.is_zero() || command.health_path.is_empty() {
        return Err(EngineDriverError::new(
            EngineFailureReason::EngineInternal,
            "engine command has invalid readiness settings",
            "allocate a loopback port, health path, and positive readiness deadline",
            false,
        ));
    }
    if command.stderr_tail_lines == 0 || command.stderr_tail_lines > 100 {
        return Err(EngineDriverError::new(
            EngineFailureReason::EngineInternal,
            "stderr_tail_lines must be between 1 and 100",
            "use a bounded stderr diagnostic tail",
            false,
        ));
    }
    if command
        .arguments
        .iter()
        .any(|argument| argument.contains('\0'))
        || command
            .environment
            .iter()
            .any(|(key, value)| key.is_empty() || key.contains('=') || value.contains('\0'))
    {
        return Err(EngineDriverError::unsafe_argument(
            "command tokens or environment contain invalid bytes",
        ));
    }
    Ok(())
}

/// Tokio subprocess executor used by production engine drivers.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioCommandExecutor;

impl TokioCommandExecutor {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn spawn_with_store(
        store: &ProcessOwnershipStore,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        Self::spawn_native(store, executable, arguments, environment, stderr_tail_lines).await
    }

    async fn spawn_native(
        #[cfg(any(target_os = "linux", target_os = "macos"))] store: &ProcessOwnershipStore,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let ownership_directory = store.open_or_create()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let spawn_result = spawn_engine_child(
            ownership_directory.as_ref(),
            executable,
            arguments,
            environment,
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let spawn_result = spawn_engine_child(executable, arguments, environment);
        let mut child = spawn_result.map_err(|error| {
            EngineDriverError::new(
                EngineFailureReason::EngineSpawnFailed,
                format!("spawn engine {:?}: {error}", executable),
                "run model-host doctor and provision a compatible engine",
                true,
            )
        })?;
        let stderr = match child.take_stderr() {
            Some(stderr) => stderr,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineSpawnFailed,
                    "engine stderr pipe was unavailable after spawn",
                    "retry with a process boundary that supports piped diagnostics",
                    true,
                ));
            }
        };
        let stderr_tail = Arc::new(StdMutex::new(BoundedStderrTail::default()));
        let capture = Arc::clone(&stderr_tail);
        let stderr_drain = std::thread::Builder::new()
            .name(format!("sbproxy-engine-stderr-{}", child.id()))
            .spawn(move || {
                let mut stderr = stderr;
                let mut buffer = [0u8; 4096];
                loop {
                    match stderr.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => capture
                            .lock()
                            .expect("engine stderr tail mutex poisoned")
                            .push(&buffer[..count]),
                    }
                }
            });
        let stderr_drain = match stderr_drain {
            Ok(stderr_drain) => stderr_drain,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineSpawnFailed,
                    format!("spawn engine stderr drain: {error}"),
                    "retry after restoring operating-system thread capacity",
                    true,
                ));
            }
        };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let ownership = {
            let record = child
                .exact_identity()
                .cloned()
                .zip(process_identity(std::process::id()))
                .map(|(mut engine, owner)| {
                    engine.executable = Some(executable.to_path_buf());
                    ManagedProcessOwnership {
                        schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                        owner,
                        process_group: engine.pid,
                        engine,
                    }
                })
                .ok_or_else(|| {
                    process_ownership_error(
                        "capture managed-engine ownership",
                        "process identity or isolated process-group proof was unavailable immediately after spawn",
                    )
                })
                .and_then(|record| store.persist_in(Arc::clone(&ownership_directory), record));
            match record {
                Ok(ownership) => ownership,
                Err(error) => {
                    child.signal_group_if_exact(libc::SIGKILL);
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stderr_drain.join();
                    return Err(error);
                }
            }
        };
        if let Err(error) = child.release_after_durable_record() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stderr_drain.join();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ownership.clear_after_verified_exit()?;
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineSpawnFailed,
                format!("exec engine {:?}: {error}", executable),
                "run model-host doctor and provision a compatible engine",
                true,
            ));
        }
        Ok(Arc::new(NativeEngineProcess {
            #[cfg(unix)]
            process_group: child.id(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ownership,
            child: StdMutex::new(child),
            stderr_tail,
            stderr_tail_lines,
            stderr_drain: StdMutex::new(Some(stderr_drain)),
        }))
    }
}

#[async_trait]
impl CommandExecutor for TokioCommandExecutor {
    async fn spawn(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let store = ProcessOwnershipStore::production();
            store.reap_stale(Duration::from_secs(2))?;
            Self::spawn_with_store(
                &store,
                executable,
                arguments,
                environment,
                stderr_tail_lines,
            )
            .await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Self::spawn_native(executable, arguments, environment, stderr_tail_lines).await
        }
    }

    async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        if timeout.is_zero() || max_output_bytes == 0 || max_output_bytes > 1024 * 1024 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "compatibility command bounds are invalid",
                "use a positive timeout and an output limit no larger than 1 MiB",
                false,
            ));
        }
        let mut command = tokio::process::Command::new(executable);
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        apply_engine_environment(command.as_std_mut(), environment);
        let output = tokio::time::timeout(timeout, command.output())
            .await
            .map_err(|_| {
                EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    format!("compatibility command {:?} timed out", executable),
                    "repair the engine environment or select another provisioning mode",
                    false,
                )
            })?
            .map_err(|error| {
                EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    format!("run compatibility command {:?}: {error}", executable),
                    "install a compatible engine environment and retry doctor",
                    false,
                )
            })?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: bounded_output(&output.stdout, max_output_bytes),
            stderr: bounded_output(&output.stderr, max_output_bytes),
        })
    }
}

fn spawn_engine_child(
    #[cfg(any(target_os = "linux", target_os = "macos"))] ownership_directory: &OwnershipDirectory,
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<SpawnedEngineChild, String> {
    spawn_engine_command(
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        ownership_directory,
        executable,
        arguments,
        environment,
    )
    .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
type NativeChild = std::process::Child;
#[cfg(target_os = "macos")]
type NativeChild = MacProcessChild;
#[cfg(target_os = "linux")]
type NativeReleaseWriter = std::process::ChildStdin;
#[cfg(target_os = "macos")]
type NativeReleaseWriter = std::fs::File;
#[cfg(target_os = "linux")]
type NativeStderrReader = std::process::ChildStderr;
#[cfg(target_os = "macos")]
type NativeStderrReader = std::fs::File;

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacProcessChild {
    pid: libc::pid_t,
}

#[cfg(target_os = "macos")]
impl MacProcessChild {
    fn id(&self) -> u32 {
        u32::try_from(self.pid).expect("posix_spawn returned a positive process ID")
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.wait_with_options(libc::WNOHANG)
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        loop {
            if let Some(status) = self.wait_with_options(0)? {
                return Ok(status);
            }
        }
    }

    fn wait_with_options(
        &mut self,
        options: libc::c_int,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        use std::os::unix::process::ExitStatusExt as _;

        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, options) };
            if result == self.pid {
                return Ok(Some(std::process::ExitStatus::from_raw(status)));
            }
            if result == 0 {
                return Ok(None);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } == 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct SpawnedEngineChild {
    child: NativeChild,
    release: Option<NativeReleaseWriter>,
    stderr: Option<NativeStderrReader>,
    status: Option<std::process::ExitStatus>,
    exact_identity: Option<ProcessIdentity>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl SpawnedEngineChild {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn take_stderr(&mut self) -> Option<NativeStderrReader> {
        self.stderr.take()
    }

    fn exact_identity(&self) -> Option<&ProcessIdentity> {
        self.exact_identity.as_ref()
    }

    fn signal_group_if_exact(&self, signal: i32) {
        if self.exact_identity.as_ref().is_some_and(|expected| {
            process_identity(self.id())
                .as_ref()
                .is_some_and(|actual| identity_matches(expected, actual))
                && process_group_for(self.id()) == Some(self.id())
        }) {
            signal_isolated_process_group(self.id(), signal);
        }
    }

    fn release_after_durable_record(&mut self) -> std::io::Result<()> {
        let mut release = self.release.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "engine startup release pipe was unavailable",
            )
        })?;
        release.write_all(b"1\n")?;
        release.flush()?;
        drop(release);
        Ok(())
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let status = self.child.try_wait()?;
        self.status = status;
        Ok(status)
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let status = self.child.wait()?;
        self.status = Some(status);
        Ok(status)
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if self.status.is_some() {
            Ok(())
        } else {
            self.child.kill()
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for SpawnedEngineChild {
    fn drop(&mut self) {
        self.release.take();
        // An unreaped direct child still owns its PID, so the operating
        // system cannot reuse that PID/process-group identity between this
        // check and the signal. Once wait reports exit, fail closed and
        // leave any surviving group member to durable recovery.
        if matches!(self.try_wait(), Ok(None)) {
            self.signal_group_if_exact(libc::SIGKILL);
            let _ = self.kill();
            let _ = self.wait();
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Debug)]
struct SpawnedEngineChild {
    child: std::process::Child,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl SpawnedEngineChild {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }

    fn release_after_durable_record(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }
}

#[cfg(target_os = "linux")]
fn spawn_engine_command(
    _ownership_directory: &OwnershipDirectory,
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> std::io::Result<SpawnedEngineChild> {
    use std::os::unix::process::CommandExt as _;

    const EXEC_GATE: &str = "IFS= read -r release || exit 125\n\
        [ \"$release\" = 1 ] || exit 125\n\
        exec </dev/null\n\
        exec \"$@\"";

    let parent_pid = unsafe { libc::getpid() };
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(EXEC_GATE)
        .arg("sbproxy-engine-gate")
        .arg(executable)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0);
    apply_engine_environment(&mut command, environment);
    // Command owns descriptor setup and the complete fork/exec boundary
    // (including atomic CLOEXEC pipes on Linux), so there is no separate
    // application-managed fork window. The child hook performs only libc
    // operations: signals stay blocked until inherited dispositions reset.
    unsafe {
        command.pre_exec(move || prepare_engine_child_signal_state(parent_pid));
    }
    // Block in the calling thread before fork so the child is protected from
    // inherited handlers from its first instruction. The child resets every
    // catchable disposition before unblocking in `pre_exec`.
    let signal_mask = ParentSignalMask::block_all()?;
    let spawn_result = command.spawn();
    signal_mask.restore()?;
    let mut child = spawn_result?;
    let exact_identity = process_identity(child.id())
        .filter(|identity| process_group_for(identity.pid) == Some(identity.pid));
    let stderr = child.stderr.take().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "engine startup gate did not provide stderr",
        )
    })?;
    let release = child.stdin.take().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "engine startup gate did not provide stdin",
        )
    })?;
    Ok(SpawnedEngineChild {
        child,
        release: Some(release),
        stderr: Some(stderr),
        status: None,
        exact_identity,
    })
}

#[cfg(target_os = "macos")]
fn spawn_engine_command(
    ownership_directory: &OwnershipDirectory,
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> std::io::Result<SpawnedEngineChild> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    const EXEC_GATE: &str = "IFS= read -r release || exit 125\n\
        [ \"$release\" = 1 ] || exit 125\n\
        exec </dev/null\n\
        exec \"$@\"";

    // Darwin has no pipe2(2). Its ordinary pipe()+FIOCLEX sequence can leak
    // one gate endpoint into a concurrent fork. Build the two channels as
    // FIFOs inside the pinned 0700 ownership directory instead: each endpoint
    // is opened atomically with O_CLOEXEC, then the names are unlinked before
    // posix_spawn. CLOEXEC_DEFAULT closes every unrelated descriptor in the
    // child, while spawn attributes install the safe signal state and group
    // without running application code after fork.
    let (release_reader, release_writer) =
        ownership_directory.create_cloexec_fifo_pair("release")?;
    let (stderr_reader, stderr_writer) = ownership_directory.create_cloexec_fifo_pair("stderr")?;
    let null_path = CString::new("/dev/null").expect("/dev/null contains no NUL");
    let null_descriptor =
        unsafe { libc::open(null_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if null_descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let null_file = unsafe { std::fs::File::from_raw_fd(null_descriptor) };

    let mut actions = MacSpawnFileActions::new()?;
    actions.dup2(release_reader.as_raw_fd(), libc::STDIN_FILENO)?;
    actions.dup2(null_file.as_raw_fd(), libc::STDOUT_FILENO)?;
    actions.dup2(stderr_writer.as_raw_fd(), libc::STDERR_FILENO)?;
    actions.close(release_reader.as_raw_fd())?;
    actions.close(null_file.as_raw_fd())?;
    actions.close(stderr_writer.as_raw_fd())?;

    let mut attributes = MacSpawnAttributes::new()?;
    let mut default_signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigfillset(&mut default_signals) } != 0
        || unsafe { libc::sigdelset(&mut default_signals, libc::SIGKILL) } != 0
        || unsafe { libc::sigdelset(&mut default_signals, libc::SIGSTOP) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut empty_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigemptyset(&mut empty_mask) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    attributes.set_signal_defaults(&default_signals)?;
    attributes.set_signal_mask(&empty_mask)?;
    attributes.set_process_group(0)?;
    attributes.set_flags(
        libc::POSIX_SPAWN_CLOEXEC_DEFAULT
            | libc::POSIX_SPAWN_SETPGROUP
            | libc::POSIX_SPAWN_SETSIGDEF
            | libc::POSIX_SPAWN_SETSIGMASK,
    )?;

    let mut argument_values = vec![
        CString::new("/bin/sh").expect("/bin/sh contains no NUL"),
        CString::new("-c").expect("-c contains no NUL"),
        CString::new(EXEC_GATE).expect("fixed gate contains no NUL"),
        CString::new("sbproxy-engine-gate").expect("fixed argv0 contains no NUL"),
        CString::new(executable.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "engine executable contains a NUL byte",
            )
        })?,
    ];
    for argument in arguments {
        argument_values.push(CString::new(argument.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "engine argument contains a NUL byte",
            )
        })?);
    }
    let mut argument_pointers = argument_values
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argument_pointers.push(std::ptr::null_mut());

    let environment_values = macos_engine_environment(environment)?;
    let mut environment_pointers = environment_values
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null_mut());

    let shell = CString::new("/bin/sh").expect("/bin/sh contains no NUL");
    let mut pid = 0;
    let result = unsafe {
        libc::posix_spawn(
            &mut pid,
            shell.as_ptr(),
            &actions.0,
            &attributes.0,
            argument_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    };
    posix_spawn_check(result)?;
    drop(release_reader);
    drop(stderr_writer);
    drop(null_file);

    let child = MacProcessChild { pid };
    let exact_identity = process_identity(child.id())
        .filter(|identity| process_group_for(identity.pid) == Some(identity.pid));
    Ok(SpawnedEngineChild {
        child,
        release: Some(release_writer),
        stderr: Some(stderr_reader),
        status: None,
        exact_identity,
    })
}

#[cfg(target_os = "macos")]
fn macos_engine_environment(overrides: &BTreeMap<String, String>) -> std::io::Result<Vec<CString>> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut values = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for key in ENGINE_ENVIRONMENT_BASELINE {
        if let Some(value) = std::env::var_os(key) {
            values.insert(
                key.as_bytes().to_vec(),
                value.as_os_str().as_bytes().to_vec(),
            );
        }
    }
    for (key, value) in overrides {
        if key.is_empty()
            || key.as_bytes().contains(&0)
            || key.as_bytes().contains(&b'=')
            || value.as_bytes().contains(&0)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "engine environment contains an invalid key or value",
            ));
        }
        values.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec());
    }
    values
        .into_iter()
        .map(|(key, value)| {
            let mut assignment = key;
            assignment.push(b'=');
            assignment.extend(value);
            CString::new(assignment).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "engine environment contains a NUL byte",
                )
            })
        })
        .collect()
}

#[cfg(target_os = "macos")]
struct MacSpawnFileActions(libc::posix_spawn_file_actions_t);

#[cfg(target_os = "macos")]
impl MacSpawnFileActions {
    fn new() -> std::io::Result<Self> {
        let mut actions = std::ptr::null_mut();
        posix_spawn_check(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
        Ok(Self(actions))
    }

    fn dup2(&mut self, source: libc::c_int, target: libc::c_int) -> std::io::Result<()> {
        posix_spawn_check(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut self.0, source, target)
        })
    }

    fn close(&mut self, descriptor: libc::c_int) -> std::io::Result<()> {
        posix_spawn_check(unsafe {
            libc::posix_spawn_file_actions_addclose(&mut self.0, descriptor)
        })
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacSpawnFileActions {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}

#[cfg(target_os = "macos")]
struct MacSpawnAttributes(libc::posix_spawnattr_t);

#[cfg(target_os = "macos")]
impl MacSpawnAttributes {
    fn new() -> std::io::Result<Self> {
        let mut attributes = std::ptr::null_mut();
        posix_spawn_check(unsafe { libc::posix_spawnattr_init(&mut attributes) })?;
        Ok(Self(attributes))
    }

    fn set_signal_defaults(&mut self, signals: &libc::sigset_t) -> std::io::Result<()> {
        posix_spawn_check(unsafe { libc::posix_spawnattr_setsigdefault(&mut self.0, signals) })
    }

    fn set_signal_mask(&mut self, signals: &libc::sigset_t) -> std::io::Result<()> {
        posix_spawn_check(unsafe { libc::posix_spawnattr_setsigmask(&mut self.0, signals) })
    }

    fn set_process_group(&mut self, process_group: libc::pid_t) -> std::io::Result<()> {
        posix_spawn_check(unsafe { libc::posix_spawnattr_setpgroup(&mut self.0, process_group) })
    }

    fn set_flags(&mut self, flags: libc::c_int) -> std::io::Result<()> {
        let flags = libc::c_short::try_from(flags).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "posix_spawn flags exceeded c_short",
            )
        })?;
        posix_spawn_check(unsafe { libc::posix_spawnattr_setflags(&mut self.0, flags) })
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacSpawnAttributes {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}

#[cfg(target_os = "macos")]
fn posix_spawn_check(result: libc::c_int) -> std::io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(result))
    }
}

#[cfg(target_os = "linux")]
struct ParentSignalMask {
    previous: libc::sigset_t,
    restored: bool,
}

#[cfg(target_os = "linux")]
impl ParentSignalMask {
    fn block_all() -> std::io::Result<Self> {
        let mut all = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigfillset(&mut all) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let result = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut previous) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        Ok(Self {
            previous,
            restored: false,
        })
    }

    fn restore(mut self) -> std::io::Result<()> {
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut())
        };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        self.restored = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for ParentSignalMask {
    fn drop(&mut self) {
        if !self.restored {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn prepare_engine_child_signal_state(parent_pid: libc::pid_t) -> std::io::Result<()> {
    let mut blocked = std::mem::zeroed::<libc::sigset_t>();
    if libc::sigfillset(&mut blocked) != 0
        || libc::sigprocmask(libc::SIG_SETMASK, &blocked, std::ptr::null_mut()) != 0
    {
        return Err(std::io::Error::last_os_error());
    }

    let mut default_action = std::mem::zeroed::<libc::sigaction>();
    default_action.sa_sigaction = libc::SIG_DFL;
    if libc::sigemptyset(&mut default_action.sa_mask) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Linux currently defines signals through 64 and Darwin through 31.
    // Probe a wider fixed range so future additions also reset; EINVAL means
    // that number is not a signal on this platform.
    for signal in 1..=128 {
        if signal == libc::SIGKILL || signal == libc::SIGSTOP {
            continue;
        }
        if libc::sigaction(signal, &default_action, std::ptr::null_mut()) != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
    }

    // No PR_SET_PDEATHSIG here. Linux delivers the parent-death signal when
    // the spawning THREAD exits, not the process, so an engine launched from a
    // pooled or short-lived thread would be killed the moment that thread
    // retires. The engine must outlive its launch thread: orphan prevention
    // before the durable record is the startup gate's read (EOF when the
    // gateway dies releases nothing and the gate exits 125), and after the
    // record it is the boot-time reap keyed on pid plus start fingerprint.
    if libc::getppid() != parent_pid {
        libc::_exit(125);
    }

    let mut empty = std::mem::zeroed::<libc::sigset_t>();
    if libc::sigemptyset(&mut empty) != 0
        || libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn spawn_engine_command(
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> std::io::Result<SpawnedEngineChild> {
    let mut command = std::process::Command::new(executable);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    apply_engine_environment(&mut command, environment);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command.spawn().map(|child| SpawnedEngineChild { child })
}

const ENGINE_ENVIRONMENT_BASELINE: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "TZ",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "SYSTEMROOT",
    "WINDIR",
];

fn apply_engine_environment(
    command: &mut std::process::Command,
    overrides: &BTreeMap<String, String>,
) {
    command.env_clear();
    for key in ENGINE_ENVIRONMENT_BASELINE {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.envs(overrides);
}

#[derive(Debug)]
struct NativeEngineProcess {
    #[cfg(unix)]
    process_group: u32,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ownership: StoredProcessOwnership,
    child: StdMutex<SpawnedEngineChild>,
    stderr_tail: Arc<StdMutex<BoundedStderrTail>>,
    stderr_tail_lines: usize,
    stderr_drain: StdMutex<Option<std::thread::JoinHandle<()>>>,
}

#[derive(Debug, Default)]
struct BoundedStderrTail {
    bytes: VecDeque<u8>,
}

impl BoundedStderrTail {
    fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes.iter().copied());
        while self.bytes.len() > MAX_STDERR_TAIL_BYTES {
            self.bytes.pop_front();
        }
    }

    fn render(&self, lines: usize) -> String {
        let bytes = self.bytes.iter().copied().collect::<Vec<_>>();
        bounded_stderr_tail(&String::from_utf8_lossy(&bytes), lines)
    }
}

impl NativeEngineProcess {
    fn join_stderr_drain(&self) {
        let mut drain = self
            .stderr_drain
            .lock()
            .expect("engine stderr drain mutex poisoned");
        if let Some(drain) = drain.take() {
            let _ = drain.join();
        }
    }

    fn try_wait(&self) -> Result<bool, EngineDriverError> {
        let exited = self
            .child
            .lock()
            .expect("engine child mutex poisoned")
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|error| {
                EngineDriverError::new(
                    EngineFailureReason::EngineHealthFailed,
                    format!("inspect engine process status: {error}"),
                    "retry the health check or restart the deployment",
                    true,
                )
            })?;
        if exited {
            #[cfg(unix)]
            {
                if process_group_exists(self.process_group) {
                    return Ok(false);
                }
            }
            // Once the complete process group is gone, every copy of the
            // stderr writer is closed. Join the drain so a fast exit cannot
            // race its final diagnostic bytes.
            self.join_stderr_drain();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                self.ownership.clear_after_verified_exit()?;
            }
        }
        Ok(exited)
    }
}

#[async_trait]
impl EngineProcess for NativeEngineProcess {
    fn id(&self) -> Option<u32> {
        self.child.lock().ok().map(|child| child.id())
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        self.try_wait()
    }

    async fn shutdown(&self, grace: Duration) -> Result<(), EngineDriverError> {
        if self.try_wait()? {
            return Ok(());
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        self.ownership.signal_group_if_exact(libc::SIGTERM)?;
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
        signal_isolated_process_group(self.process_group, libc::SIGTERM);
        #[cfg(not(unix))]
        self.child
            .lock()
            .expect("engine child mutex poisoned")
            .kill()
            .map_err(shutdown_error)?;

        let deadline = tokio::time::Instant::now() + grace;
        while tokio::time::Instant::now() < deadline {
            if self.try_wait()? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        self.ownership.signal_group_if_exact(libc::SIGKILL)?;
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
        signal_isolated_process_group(self.process_group, libc::SIGKILL);
        self.child
            .lock()
            .expect("engine child mutex poisoned")
            .kill()
            .map_err(shutdown_error)?;
        let forced_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < forced_deadline {
            if self.try_wait()? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(EngineDriverError::new(
            EngineFailureReason::EngineShutdownFailed,
            "engine process did not exit after forced termination",
            "terminate the isolated engine process group and retry the operation",
            true,
        ))
    }

    fn stderr_tail(&self) -> String {
        self.stderr_tail
            .lock()
            .expect("engine stderr tail mutex poisoned")
            .render(self.stderr_tail_lines)
    }
}

impl Drop for NativeEngineProcess {
    fn drop(&mut self) {
        let drain = self
            .stderr_drain
            .get_mut()
            .expect("engine stderr drain mutex poisoned during drop");
        let child = self
            .child
            .get_mut()
            .expect("engine child mutex poisoned during drop");
        let child_exited = child.try_wait().ok().flatten().is_some();
        let drain_finished = drain
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished);
        #[cfg(unix)]
        let process_group_running = process_group_exists(self.process_group);
        let should_terminate_group = !child_exited || !drain_finished || {
            #[cfg(unix)]
            {
                process_group_running
            }
            #[cfg(not(unix))]
            {
                false
            }
        };
        if should_terminate_group {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if self.ownership.exact_engine_owns_recorded_group() {
                signal_isolated_process_group(self.process_group, libc::SIGKILL);
            } else if process_group_running {
                tracing::warn!(
                    process_group = self.process_group,
                    "retaining managed-engine ownership because drop cannot prove the occupied process group"
                );
            }
            #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
            signal_isolated_process_group(self.process_group, libc::SIGKILL);
        }
        if !child_exited {
            let _ = child.kill();
            let _ = child.wait();
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if child.try_wait().ok().flatten().is_some()
            && wait_for_process_group_exit(self.process_group, Duration::from_secs(5))
        {
            if let Err(error) = self.ownership.clear_after_verified_exit() {
                tracing::warn!(error = %error, "failed to clear verified managed-engine ownership");
            }
        }
        if let Some(drain) = drain.take() {
            let _ = drain.join();
        }
    }
}

fn shutdown_error(error: std::io::Error) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineShutdownFailed,
        format!("stop engine process: {error}"),
        "stop the deployment again or terminate the isolated engine process group",
        true,
    )
}

/// Production loopback HTTP readiness probe.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoopbackReadinessProbe;

#[async_trait]
impl EngineReadinessProbe for LoopbackReadinessProbe {
    async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError> {
        let attempt = async {
            let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .ok()?;
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).await.ok()?;
            let mut buffer = [0u8; 64];
            let count = stream.read(&mut buffer).await.ok()?;
            let head = String::from_utf8_lossy(&buffer[..count]);
            Some(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"))
        };
        Ok(matches!(
            tokio::time::timeout(Duration::from_secs(2), attempt).await,
            Ok(Some(true))
        ))
    }
}

fn bounded_stderr_tail(contents: &str, lines: usize) -> String {
    let retained = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .rev()
        .take(lines)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    redact_engine_output(&retained.chars().take(8_192).collect::<String>())
}

fn redact_engine_output(output: &str) -> String {
    let mut tokens = output.split_whitespace().peekable();
    let mut redacted = Vec::new();
    while let Some(token) = tokens.next() {
        redacted.push(token.to_string());
        if (token.eq_ignore_ascii_case("bearer")
            || matches!(token, "--api-key" | "--token" | "--hf-token"))
            && tokens.next().is_some()
        {
            redacted.push("[REDACTED]".to_string());
        }
    }
    redacted.join(" ")
}

fn bounded_output(output: &[u8], max_output_bytes: usize) -> String {
    let end = output.len().min(max_output_bytes);
    redact_engine_output(&String::from_utf8_lossy(&output[..end]))
}

#[cfg(unix)]
fn process_group_for(pid: u32) -> Option<u32> {
    let pid = libc::pid_t::try_from(pid).ok()?;
    if pid <= 0 {
        return None;
    }
    let process_group = unsafe { libc::getpgid(pid) };
    u32::try_from(process_group).ok()
}

#[cfg(unix)]
fn process_group_exists(process_group: u32) -> bool {
    let process_group = process_group as libc::pid_t;
    if process_group <= 0 {
        return false;
    }
    let result = unsafe { libc::kill(-process_group, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(unix)]
fn signal_isolated_process_group(process_group: u32, signal: i32) {
    let process_group = process_group as libc::pid_t;
    // SAFETY: getpgrp has no preconditions, and kill receives the negative
    // process-group ID created for this managed engine.
    unsafe {
        if process_group > 0 && process_group != libc::getpgrp() {
            let _ = libc::kill(-process_group, signal);
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::process::CommandExt as _;

    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[derive(Debug)]
    struct NeverReady;

    #[async_trait]
    impl EngineReadinessProbe for NeverReady {
        async fn ready(&self, _port: u16, _path: &str) -> Result<bool, EngineDriverError> {
            Ok(false)
        }
    }

    struct IsolatedChild(std::process::Child);

    impl IsolatedChild {
        fn sleep() -> Self {
            let mut command = std::process::Command::new("/bin/sleep");
            command.arg("60").process_group(0);
            Self(command.spawn().expect("spawn isolated sleep fixture"))
        }

        fn id(&self) -> u32 {
            self.0.id()
        }

        fn is_running(&mut self) -> bool {
            match self.0.try_wait() {
                Ok(status) => status.is_none(),
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => false,
                Err(error) => panic!("poll fixture: {error}"),
            }
        }
    }

    impl Drop for IsolatedChild {
        fn drop(&mut self) {
            signal_isolated_process_group(self.0.id(), libc::SIGKILL);
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn missing_owner_identity() -> ProcessIdentity {
        ProcessIdentity {
            pid: u32::MAX,
            start_fingerprint: u64::MAX,
            executable: None,
        }
    }

    #[test]
    fn recovery_does_not_create_a_missing_ownership_directory() {
        let parent = tempfile::tempdir().unwrap();
        let selected = parent.path().join("managed-engines");
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let store = ProcessOwnershipStore::at(&selected);

        let recovered = store
            .reap_stale(Duration::from_millis(10))
            .expect("an absent store means there is nothing to recover");

        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(recovered, 0);
        assert!(
            !selected.exists(),
            "pure proxy boot must not create ownership state"
        );
    }

    #[test]
    fn ownership_persist_creates_a_private_effective_uid_directory() {
        let parent = tempfile::tempdir().unwrap();
        let selected = parent.path().join("managed-engines");
        let store = ProcessOwnershipStore::at(&selected);

        let ownership = store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: ProcessIdentity {
                    pid: u32::MAX - 1,
                    start_fingerprint: u64::MAX - 1,
                    executable: None,
                },
                process_group: u32::MAX - 1,
            })
            .expect("persist ownership");

        let metadata = std::fs::symlink_metadata(&selected).expect("created ownership directory");
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        ownership.clear_after_verified_exit().unwrap();
    }

    #[test]
    fn ownership_store_rejects_a_symlink_selected_as_its_directory() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("attacker-controlled");
        let selected = parent.path().join("managed-engines");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &selected).unwrap();
        let store = ProcessOwnershipStore::at(&selected);

        let error = store
            .record_paths()
            .expect_err("ownership directory symlink must fail closed");
        assert!(error.to_string().contains("ownership directory"), "{error}");
    }

    #[test]
    fn ownership_store_rejects_a_symlinked_parent_directory() {
        let root = tempfile::tempdir().unwrap();
        let real_parent = root.path().join("real-parent");
        let selected_parent = root.path().join("selected-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &selected_parent).unwrap();
        let store = ProcessOwnershipStore::at(selected_parent.join("managed-engines"));

        let error = store
            .ensure_private_directory()
            .expect_err("ownership parent symlink must fail closed");

        assert!(error.to_string().contains("ownership directory"), "{error}");
    }

    #[test]
    fn ownership_store_rejects_a_symlink_in_an_ancestor_directory() {
        let root = tempfile::tempdir().unwrap();
        let real_ancestor = root.path().join("real-ancestor");
        let selected_ancestor = root.path().join("selected-ancestor");
        std::fs::create_dir(&real_ancestor).unwrap();
        std::os::unix::fs::symlink(&real_ancestor, &selected_ancestor).unwrap();
        let store = ProcessOwnershipStore::at(selected_ancestor.join("nested/managed-engines"));

        let error = store
            .ensure_private_directory()
            .expect_err("every ownership-path component must be opened without following links");

        assert!(error.to_string().contains("ownership directory"), "{error}");
        assert!(
            !real_ancestor.join("nested").exists(),
            "recursive creation must not cross an ancestor symlink"
        );
    }

    #[test]
    fn ownership_store_rejects_a_writable_non_sticky_parent_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let store = ProcessOwnershipStore::at(root.path().join("managed-engines"));

        let error = store
            .ensure_private_directory()
            .expect_err("untrusted writers must not replace the ownership directory");

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(error.to_string().contains("ownership directory"), "{error}");
    }

    #[test]
    fn ownership_store_rejects_a_writable_non_sticky_ancestor_directory() {
        let root = tempfile::tempdir().unwrap();
        let unsafe_ancestor = root.path().join("unsafe-ancestor");
        let safe_parent = unsafe_ancestor.join("safe-parent");
        std::fs::create_dir(&unsafe_ancestor).unwrap();
        std::fs::create_dir(&safe_parent).unwrap();
        std::fs::set_permissions(&unsafe_ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::set_permissions(&safe_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = ProcessOwnershipStore::at(safe_parent.join("managed-engines"));

        let error = store
            .ensure_private_directory()
            .expect_err("an unsafe ancestor must not be hidden by a private immediate parent");

        std::fs::set_permissions(&unsafe_ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(error.to_string().contains("ownership directory"), "{error}");
    }

    #[test]
    fn ownership_store_rejects_a_permissive_precreated_directory() {
        let parent = tempfile::tempdir().unwrap();
        let selected = parent.path().join("managed-engines");
        std::fs::create_dir(&selected).unwrap();
        std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o777)).unwrap();
        let store = ProcessOwnershipStore::at(&selected);

        let error = store
            .record_paths()
            .expect_err("permissive ownership directory must fail closed");
        assert!(error.to_string().contains("ownership directory"), "{error}");
    }

    #[test]
    fn ownership_store_tightens_an_owner_only_writable_legacy_directory() {
        let parent = tempfile::tempdir().unwrap();
        let selected = parent.path().join("managed-engines");
        std::fs::create_dir(&selected).unwrap();
        std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o755)).unwrap();
        let store = ProcessOwnershipStore::at(&selected);

        store
            .ensure_private_directory()
            .expect("a spawn may tighten an owner-only legacy directory");
        let mode = std::fs::symlink_metadata(&selected)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn ownership_store_tightens_a_legacy_directory_on_the_read_path() {
        // Boot recovery opens the directory without creating it. A 0755
        // directory left by a pre-hardening binary must be repaired there
        // too, or the first boot after an upgrade fails (WOR-2167).
        let parent = tempfile::tempdir().unwrap();
        let selected = parent.path().join("managed-engines");
        std::fs::create_dir(&selected).unwrap();
        std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o755)).unwrap();
        let store = ProcessOwnershipStore::at(&selected);

        store
            .record_paths()
            .expect("a read may tighten an owner-only legacy directory");
        let mode = std::fs::symlink_metadata(&selected)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn ownership_store_rejects_a_directory_owned_by_another_uid() {
        // `/` is always a real directory and is owned by root. This process
        // only exercises the wrong-owner branch when it is not itself root.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let store = ProcessOwnershipStore::at("/");

        let error = store
            .record_paths()
            .expect_err("wrong-owner ownership directory must fail closed");
        assert!(error.to_string().contains("ownership directory"), "{error}");
    }

    #[test]
    fn ownership_store_rejects_an_oversized_record_before_reading_it() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        store.ensure_private_directory().unwrap();
        let record = store.directory.join("oversized.json");
        let file = std::fs::File::create(&record).unwrap();
        file.set_len((MAX_PROCESS_OWNERSHIP_RECORD_BYTES + 1) as u64)
            .unwrap();

        let error = store
            .records()
            .expect_err("boot recovery must bound ownership-record allocation");

        assert!(error.to_string().contains("size limit"), "{error}");
    }

    #[test]
    fn ownership_store_bounds_the_number_of_records() {
        let mut names = (0..MAX_PROCESS_OWNERSHIP_RECORDS)
            .map(|index| OsString::from(format!("{index}.json")))
            .collect::<Vec<_>>();

        let error = push_bounded_record_name(&mut names, OsString::from("overflow.json"))
            .expect_err("boot recovery must bound record enumeration");

        assert!(error.to_string().contains("record limit"), "{error}");
    }

    #[test]
    fn stored_ownership_remains_pinned_when_the_selected_path_is_replaced() {
        let parent = tempfile::tempdir().unwrap();
        let selected = parent.path().join("managed-engines");
        let moved = parent.path().join("original-managed-engines");
        let store = ProcessOwnershipStore::at(&selected);
        let ownership = store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: ProcessIdentity {
                    pid: u32::MAX - 2,
                    start_fingerprint: u64::MAX - 2,
                    executable: None,
                },
                process_group: u32::MAX - 2,
            })
            .expect("persist ownership before path replacement");
        std::fs::rename(&selected, &moved).unwrap();
        std::fs::create_dir(&selected).unwrap();
        std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o700)).unwrap();
        let attacker_record = selected.join(&ownership.name);
        std::fs::write(&attacker_record, b"must remain").unwrap();

        ownership
            .clear_after_verified_exit()
            .expect("clear through pinned directory");

        assert!(
            !moved.join(&ownership.name).exists(),
            "the original pinned record must be removed"
        );
        assert!(
            attacker_record.exists(),
            "a replacement path must never redirect record removal"
        );
    }

    #[test]
    fn ownership_store_does_not_follow_a_record_symlink() {
        let parent = tempfile::tempdir().unwrap();
        let selected = parent.path().join("managed-engines");
        let store = ProcessOwnershipStore::at(&selected);
        let ownership = store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: ProcessIdentity {
                    pid: u32::MAX - 3,
                    start_fingerprint: u64::MAX - 3,
                    executable: None,
                },
                process_group: u32::MAX - 3,
            })
            .expect("persist record to replace");
        let record = selected.join(&ownership.name);
        let target = parent.path().join("untrusted-record.json");
        std::fs::rename(&record, &target).unwrap();
        std::os::unix::fs::symlink(&target, &record).unwrap();

        let error = store
            .records()
            .expect_err("record symlinks must fail closed");

        assert!(error.to_string().contains("ownership"), "{error}");
    }

    #[test]
    fn stale_exact_owned_process_is_reaped_without_a_name_sweep() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let mut engine = IsolatedChild::sleep();
        let engine_identity = process_identity(engine.id()).expect("engine identity");
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: engine_identity,
                process_group: engine.id(),
            })
            .expect("persist stale ownership");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(100))
                .expect("reap exact stale engine"),
            1
        );
        assert!(!engine.is_running(), "exact stale engine must exit");
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[test]
    fn stale_reap_waits_for_the_entire_managed_process_group() {
        let directory = tempfile::tempdir().unwrap();
        let descendant_path = directory.path().join("descendant.pid");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                "trap '' TERM; /bin/sleep 60 & child=$!; echo \"$child\" > \"$1\"; wait \"$child\"",
                "sbproxy-process-group-fixture",
                descendant_path.to_str().unwrap(),
            ])
            .process_group(0);
        let mut engine = IsolatedChild(command.spawn().expect("spawn process-group fixture"));
        let descendant_pid = {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(contents) = std::fs::read_to_string(&descendant_path) {
                    if let Ok(pid) = contents.trim().parse::<u32>() {
                        break pid;
                    }
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "fixture did not publish descendant pid"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: process_identity(engine.id()).expect("engine identity"),
                process_group: engine.id(),
            })
            .expect("persist process-group ownership");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(100))
                .expect("reap exact stale process group"),
            1
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while process_identity(descendant_pid).is_some() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            process_identity(descendant_pid).is_none(),
            "ownership must remain actionable until every process-group descendant exits"
        );
        assert!(!engine.is_running(), "process-group leader must exit");
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[test]
    fn reused_pid_with_wrong_start_fingerprint_is_never_signalled() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let mut unrelated = IsolatedChild::sleep();
        let mut mismatched = process_identity(unrelated.id()).expect("unrelated identity");
        mismatched.start_fingerprint = mismatched.start_fingerprint.wrapping_add(1);
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: mismatched,
                process_group: unrelated.id(),
            })
            .expect("persist reused-pid fixture");

        let error = store
            .reap_stale(Duration::from_millis(50))
            .expect_err("an occupied ambiguous process group must fail closed");
        assert!(
            unrelated.is_running(),
            "fingerprint mismatch must preserve unrelated process"
        );
        assert_eq!(store.record_paths().unwrap().len(), 1);
        assert!(error.to_string().contains("cannot prove"), "{error}");
    }

    #[test]
    fn exited_engine_leader_with_a_live_group_member_is_not_signalled_or_forgotten() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let descendant_path = directory.path().join("descendant.pid");
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                "IFS= read -r release; /bin/sleep 60 & echo \"$!\" > \"$1\"",
                "sbproxy-ambiguous-group-fixture",
                descendant_path.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .process_group(0);
        let mut leader = command.spawn().expect("spawn process-group leader");
        let leader_identity = process_identity(leader.id()).expect("capture exact leader");
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: leader_identity,
                process_group: leader.id(),
            })
            .expect("persist exact leader");
        leader
            .stdin
            .take()
            .unwrap()
            .write_all(b"release\n")
            .unwrap();
        leader
            .wait()
            .expect("leader exits after starting descendant");
        let descendant_pid = {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(contents) = std::fs::read_to_string(&descendant_path) {
                    if let Ok(pid) = contents.trim().parse::<u32>() {
                        break pid;
                    }
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "fixture did not publish descendant pid"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };

        let error = store
            .reap_stale(Duration::from_millis(50))
            .expect_err("a group without its exact recorded leader is ambiguous");

        assert!(
            process_identity(descendant_pid).is_some(),
            "ambiguous process-group member must not be signalled"
        );
        assert_eq!(store.record_paths().unwrap().len(), 1);
        assert!(error.to_string().contains("cannot prove"), "{error}");
        signal_isolated_process_group(leader.id(), libc::SIGKILL);
    }

    #[test]
    fn matching_pid_and_start_is_reaped_when_executable_audit_path_changed() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let mut engine = IsolatedChild::sleep();
        let mut recorded = process_identity(engine.id()).expect("engine identity");
        recorded.executable = Some(PathBuf::from("/previous/path/to/the-same-executable"));
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: recorded,
                process_group: engine.id(),
            })
            .expect("persist executable-audit fixture");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(50))
                .expect("reap exact engine after executable replacement"),
            1
        );
        assert!(
            !engine.is_running(),
            "PID and start fingerprint identify the exact managed engine"
        );
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[test]
    fn live_owner_is_preserved_when_its_executable_audit_path_changed() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let mut engine = IsolatedChild::sleep();
        let mut owner = process_identity(std::process::id()).expect("test owner identity");
        owner.executable = Some(PathBuf::from("/previous/path/to/the-same-owner"));
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner,
                engine: process_identity(engine.id()).expect("engine identity"),
                process_group: engine.id(),
            })
            .expect("persist live ownership with replaced executable");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(50))
                .expect("inspect live owner after executable replacement"),
            0
        );
        assert!(
            engine.is_running(),
            "a live exact owner must preserve its managed engine"
        );
        assert_eq!(store.record_paths().unwrap().len(), 1);
    }

    #[test]
    fn exact_live_owner_prevents_reaping() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let mut engine = IsolatedChild::sleep();
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: process_identity(std::process::id()).expect("test owner identity"),
                engine: process_identity(engine.id()).expect("engine identity"),
                process_group: engine.id(),
            })
            .expect("persist live ownership");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(50))
                .expect("inspect live owner"),
            0
        );
        assert!(engine.is_running(), "live owner's engine must be preserved");
        assert_eq!(store.record_paths().unwrap().len(), 1);
    }

    #[test]
    fn killed_owner_allows_exact_engine_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let mut owner = IsolatedChild::sleep();
        let mut engine = IsolatedChild::sleep();
        let owner_pid = owner.id();
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: process_identity(owner.id()).expect("owner identity"),
                engine: process_identity(engine.id()).expect("engine identity"),
                process_group: engine.id(),
            })
            .expect("persist subprocess ownership");

        owner.0.kill().expect("SIGKILL owner fixture");
        owner.0.wait().expect("reap owner fixture");
        assert_eq!(
            store
                .reap_owned_by(
                    owner_pid,
                    Duration::from_millis(100),
                    Duration::from_millis(100),
                )
                .expect("recover after killed owner"),
            1
        );
        assert!(!engine.is_running(), "killed owner's engine must be reaped");
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[test]
    fn owner_scoped_recovery_does_not_reap_an_unrelated_stale_engine() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let mut owner = IsolatedChild::sleep();
        let mut owned_engine = IsolatedChild::sleep();
        let mut unrelated_engine = IsolatedChild::sleep();
        let owner_pid = owner.id();
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: process_identity(owner_pid).expect("owner identity"),
                engine: process_identity(owned_engine.id()).expect("owned engine identity"),
                process_group: owned_engine.id(),
            })
            .unwrap();
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: process_identity(unrelated_engine.id()).expect("unrelated engine identity"),
                process_group: unrelated_engine.id(),
            })
            .unwrap();
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();

        let reaped = store
            .reap_owned_by(
                owner_pid,
                Duration::from_millis(100),
                Duration::from_millis(100),
            )
            .expect("reap only the requested owner's engines");

        assert_eq!(reaped, 1);
        assert!(!owned_engine.is_running());
        assert!(
            unrelated_engine.is_running(),
            "a service retry must not turn into generic stale-engine reaping"
        );
        assert_eq!(store.record_paths().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn verified_normal_shutdown_clears_durable_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let process = TokioCommandExecutor::spawn_with_store(
            &store,
            Path::new("/bin/sleep"),
            &["60".to_string()],
            &BTreeMap::new(),
            20,
        )
        .await
        .expect("spawn managed fixture");

        assert_eq!(store.record_paths().unwrap().len(), 1);
        process
            .shutdown(Duration::from_millis(100))
            .await
            .expect("shutdown managed fixture");
        assert!(process.has_exited().await.unwrap());
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[tokio::test]
    async fn active_shutdown_does_not_signal_a_group_after_its_exact_leader_exits() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let descendant_path = directory.path().join("descendant.pid");
        let process = TokioCommandExecutor::spawn_with_store(
            &store,
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "/bin/sleep 60 & echo \"$!\" > \"$1\"".to_string(),
                "sbproxy-active-ambiguous-group".to_string(),
                descendant_path.display().to_string(),
            ],
            &BTreeMap::new(),
            20,
        )
        .await
        .expect("spawn managed group fixture");
        let process_group = process.id().unwrap();
        let descendant_pid = {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(contents) = std::fs::read_to_string(&descendant_path) {
                    if let Ok(pid) = contents.trim().parse::<u32>() {
                        if process_identity(process_group).is_none() {
                            break pid;
                        }
                    }
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "fixture leader did not exit"
                );
                tokio::task::yield_now().await;
            }
        };

        let error = process
            .shutdown(Duration::from_millis(20))
            .await
            .expect_err("shutdown must fail closed without its exact group leader");

        assert!(error.to_string().contains("cannot prove"), "{error}");
        assert!(process_identity(descendant_pid).is_some());
        assert_eq!(store.record_paths().unwrap().len(), 1);
        signal_isolated_process_group(process_group, libc::SIGKILL);
        assert!(wait_for_process_group_exit(
            process_group,
            Duration::from_secs(2)
        ));
    }

    fn test_gate_directory(directory: &tempfile::TempDir) -> Arc<OwnershipDirectory> {
        ProcessOwnershipStore::at(directory.path().join("gate-ownership"))
            .open_or_create()
            .expect("open private gate directory")
    }

    #[test]
    fn engine_cannot_exec_before_ownership_can_be_made_durable() {
        let directory = tempfile::tempdir().unwrap();
        let gate_directory = test_gate_directory(&directory);
        let marker = directory.path().join("engine-executed");
        let mut child = spawn_engine_child(
            gate_directory.as_ref(),
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "printf executed > \"$1\"; sleep 60".to_string(),
                "sbproxy-durable-spawn-fixture".to_string(),
                marker.display().to_string(),
            ],
            &BTreeMap::new(),
        )
        .expect("prepare managed child");

        std::thread::sleep(Duration::from_millis(100));
        let executed_early = marker.exists();
        let _ = child.kill();
        let _ = child.wait();

        assert!(
            !executed_early,
            "the engine executed before its ownership record was durable"
        );
    }

    #[test]
    fn startup_control_eof_exits_without_executing_the_engine() {
        let directory = tempfile::tempdir().unwrap();
        let gate_directory = test_gate_directory(&directory);
        let marker = directory.path().join("engine-executed");
        let mut child = spawn_engine_child(
            gate_directory.as_ref(),
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "printf executed > \"$1\"".to_string(),
                "sbproxy-parent-death-fixture".to_string(),
                marker.display().to_string(),
            ],
            &BTreeMap::new(),
        )
        .expect("prepare managed child");

        child.release.take();
        let status = child.wait().expect("wait after startup-control EOF");

        assert!(!status.success());
        assert!(
            !marker.exists(),
            "startup-control EOF must exit before engine exec"
        );
    }

    #[test]
    fn unreleased_child_group_signal_requires_the_captured_start_fingerprint() {
        let directory = tempfile::tempdir().unwrap();
        let gate_directory = test_gate_directory(&directory);
        let mut child = spawn_engine_child(
            gate_directory.as_ref(),
            Path::new("/bin/sleep"),
            &["60".to_string()],
            &BTreeMap::new(),
        )
        .expect("prepare managed child");
        let captured_start = child
            .exact_identity
            .as_ref()
            .expect("capture gated child identity")
            .start_fingerprint;
        child
            .exact_identity
            .as_mut()
            .expect("capture gated child identity")
            .start_fingerprint = captured_start.wrapping_add(1);

        child.signal_group_if_exact(libc::SIGKILL);

        assert!(
            child.try_wait().unwrap().is_none(),
            "group signalling must fail closed after an identity mismatch"
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn concurrent_spawn_gates_keep_release_handles_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let gate_directory = test_gate_directory(&directory);
        let mut workers = Vec::new();
        for index in 0..8 {
            let marker = directory.path().join(format!("engine-{index}-executed"));
            let gate_directory = Arc::clone(&gate_directory);
            workers.push((
                marker.clone(),
                std::thread::spawn(move || {
                    spawn_engine_child(
                        gate_directory.as_ref(),
                        Path::new("/bin/sh"),
                        &[
                            "-c".to_string(),
                            "printf executed > \"$1\"".to_string(),
                            format!("sbproxy-concurrent-gate-{index}"),
                            marker.display().to_string(),
                        ],
                        &BTreeMap::new(),
                    )
                    .expect("spawn isolated startup gate")
                }),
            ));
        }
        let mut children = workers
            .into_iter()
            .map(|(marker, worker)| (marker, worker.join().unwrap()))
            .collect::<Vec<_>>();
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            children.iter().all(|(marker, _)| !marker.exists()),
            "one startup pipe must never release another concurrent child"
        );

        for (_, child) in &mut children {
            child.release_after_durable_record().unwrap();
        }
        for (marker, child) in &mut children {
            assert!(child.wait().unwrap().success());
            assert!(marker.exists());
        }
    }

    #[test]
    fn spawn_gate_resets_an_inherited_blocked_signal_mask() {
        let directory = tempfile::tempdir().unwrap();
        let gate_directory = test_gate_directory(&directory);
        let marker = directory.path().join("survived-sigterm");
        let status = std::thread::spawn(move || {
            let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
            assert_eq!(unsafe { libc::sigemptyset(&mut blocked) }, 0);
            assert_eq!(unsafe { libc::sigaddset(&mut blocked, libc::SIGTERM) }, 0);
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut(),) },
                0
            );
            let mut child = spawn_engine_child(
                gate_directory.as_ref(),
                Path::new("/bin/sh"),
                &[
                    "-c".to_string(),
                    "kill -TERM $$; printf survived > \"$1\"".to_string(),
                    "sbproxy-signal-reset-fixture".to_string(),
                    marker.display().to_string(),
                ],
                &BTreeMap::new(),
            )
            .expect("spawn with a blocked caller signal");
            child.release_after_durable_record().unwrap();
            let status = child.wait().unwrap();
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &blocked, std::ptr::null_mut()) },
                0
            );
            status
        })
        .join()
        .unwrap();

        assert!(
            !status.success(),
            "SIGTERM must use its default disposition"
        );
        assert!(
            !directory.path().join("survived-sigterm").exists(),
            "the engine inherited a blocked SIGTERM mask"
        );
    }

    #[tokio::test]
    async fn durable_write_failure_reaps_the_unreleased_child() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::failing_at(directory.path().join("ownership"));
        let marker = directory.path().join("engine-executed");

        let error = TokioCommandExecutor::spawn_with_store(
            &store,
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "printf executed > \"$1\"; sleep 60".to_string(),
                "sbproxy-failed-persist-fixture".to_string(),
                marker.display().to_string(),
            ],
            &BTreeMap::new(),
            20,
        )
        .await
        .expect_err("injected durable write must fail the spawn");

        assert!(
            error.to_string().contains("durable-write failure"),
            "{error}"
        );
        assert!(
            !marker.exists(),
            "a child whose durable write failed must never execute"
        );
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exec_failure_is_reported_as_an_early_exit_and_clears_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));

        let process = TokioCommandExecutor::spawn_with_store(
            &store,
            Path::new("/definitely/missing/sbproxy-engine"),
            &[],
            &BTreeMap::new(),
            20,
        )
        .await
        .expect("the durable gate starts before it attempts engine exec");
        tokio::time::timeout(Duration::from_secs(2), async {
            while !process.has_exited().await.unwrap() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed exec exits promptly");

        assert!(
            process.stderr_tail().contains("sbproxy-engine"),
            "{}",
            process.stderr_tail()
        );
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[tokio::test]
    async fn fast_exit_preserves_the_typed_early_exit_and_stderr() {
        let runner = EngineProcessRunner::new(Arc::new(TokioCommandExecutor), Arc::new(NeverReady))
            .with_poll_interval(Duration::from_millis(1));
        let command = EngineCommand {
            executable: PathBuf::from("/bin/sh"),
            arguments: vec![
                "-c".to_string(),
                "echo FAST-EXIT-DIAGNOSTIC >&2; exit 42".to_string(),
            ],
            environment: BTreeMap::new(),
            port: 9,
            health_path: "/health".to_string(),
            ready_timeout: Duration::from_secs(2),
            stderr_tail_lines: 20,
        };

        let error = runner
            .launch(&command)
            .await
            .expect_err("fast exit must fail before readiness");

        assert_eq!(error.reason(), EngineFailureReason::EngineEarlyExit);
        assert_eq!(error.diagnostic_tail(), Some("FAST-EXIT-DIAGNOSTIC"));
    }

    #[tokio::test]
    async fn durable_spawn_resolves_path_and_keeps_the_typed_environment_boundary() {
        // Lock first, then mutate: the guard restores the sentinel on
        // drop (before the lock releases), panic included (WOR-646).
        let _guard = ENV_LOCK.lock().await;
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "SBPROXY_ENGINE_SECRET_SENTINEL",
            Some("must-not-leak"),
        )]);
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path().join("ownership"));
        let process = TokioCommandExecutor::spawn_with_store(
            &store,
            Path::new("sh"),
            &[
                "-c".to_string(),
                "printf '%s|%s\\n' \"$SBPROXY_TYPED_VISIBLE\" \"${SBPROXY_ENGINE_SECRET_SENTINEL:-}\" >&2"
                    .to_string(),
            ],
            &BTreeMap::from([
                ("PATH".to_string(), "/bin:/usr/bin".to_string()),
                ("SBPROXY_TYPED_VISIBLE".to_string(), "yes".to_string()),
            ]),
            20,
        )
        .await
        .expect("spawn through typed PATH");

        tokio::time::timeout(Duration::from_secs(2), async {
            while !process.has_exited().await.unwrap() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("typed environment fixture exits");
        assert_eq!(process.stderr_tail(), "yes|");
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[tokio::test]
    async fn compatibility_process_receives_only_baseline_and_typed_environment() {
        // Lock first, then mutate: the guard restores the sentinel on
        // drop (before the lock releases), panic included (WOR-646).
        let _guard = ENV_LOCK.lock().await;
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "SBPROXY_ENGINE_SECRET_SENTINEL",
            Some("must-not-leak"),
        )]);
        let output = TokioCommandExecutor
            .output(
                Path::new("/usr/bin/env"),
                &[],
                &BTreeMap::from([("SBPROXY_TYPED_VISIBLE".to_string(), "yes".to_string())]),
                Duration::from_secs(2),
                64 * 1024,
            )
            .await
            .unwrap();

        assert!(output.stdout.contains("SBPROXY_TYPED_VISIBLE=yes"));
        assert!(!output.stdout.contains("SBPROXY_ENGINE_SECRET_SENTINEL"));
        assert!(!output.stdout.contains("must-not-leak"));
    }

    #[tokio::test]
    async fn engine_stderr_is_retained_only_in_a_bounded_memory_tail() {
        let process = TokioCommandExecutor
            .spawn(
                Path::new("/bin/sh"),
                &[
                    "-c".to_string(),
                    "i=0; while [ $i -lt 12000 ]; do echo noise-$i >&2; i=$((i+1)); done; echo FINAL-MARKER >&2"
                        .to_string(),
                ],
                &BTreeMap::new(),
                20,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !process.has_exited().await.unwrap() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let tail = process.stderr_tail();
        assert!(tail.contains("FINAL-MARKER"));
        assert!(tail.len() <= 8_192);
        assert!(tail.lines().count() <= 20);
    }

    #[test]
    fn engine_stderr_capture_survives_the_launch_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let release = directory.path().join("release");
        let release_arg = release.display().to_string();
        let process = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(TokioCommandExecutor.spawn(
                Path::new("/bin/sh"),
                &[
                    "-c".to_string(),
                    "echo BEFORE-RUNTIME-DROP >&2; while [ ! -f \"$1\" ]; do sleep 0.01; done; echo AFTER-RUNTIME-DROP >&2; sleep 5"
                        .to_string(),
                    "sbproxy-stderr-fixture".to_string(),
                    release_arg,
                ],
                &BTreeMap::new(),
                20,
            ))
        })
        .join()
        .unwrap()
        .unwrap();

        std::fs::write(&release, b"release").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                while !process.stderr_tail().contains("AFTER-RUNTIME-DROP") {
                    assert!(
                        !process.has_exited().await.unwrap(),
                        "engine exited when its launch runtime dropped"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("stderr emitted after runtime drop must remain readable");
            assert!(!process.has_exited().await.unwrap());
            process.shutdown(Duration::from_millis(100)).await.unwrap();
        });
    }
}
