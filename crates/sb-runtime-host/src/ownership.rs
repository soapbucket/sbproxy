// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Durable, exact-generation ownership for native managed processes.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {

    use std::ffi::{CStr, CString, OsStr, OsString};
    use std::io::{Read as _, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use sb_runtime_core::{EngineDriverError, EngineFailureReason};
    use serde::{Deserialize, Serialize};

    const SCHEMA_VERSION: u32 = 1;
    const MAX_RECORD_BYTES: usize = 64 * 1024;
    const MAX_RECORDS: usize = 4_096;
    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ProcessIdentity {
        pid: u32,
        start_fingerprint: u64,
        executable: Option<PathBuf>,
    }

    /// Exact identity of a process generation that owns managed engines.
    ///
    /// The executable is audit context only. PID plus start fingerprint is the
    /// authority used for matching, so PID reuse cannot authorize cleanup.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ManagedEngineOwner {
        pid: u32,
        start_fingerprint: u64,
        executable: Option<PathBuf>,
    }

    impl ManagedEngineOwner {
        /// Return whether both tokens name the same process generation.
        pub fn same_process_generation(&self, other: &Self) -> bool {
            self.pid == other.pid && self.start_fingerprint == other.start_fingerprint
        }

        fn identity(&self) -> ProcessIdentity {
            ProcessIdentity {
                pid: self.pid,
                start_fingerprint: self.start_fingerprint,
                executable: self.executable.clone(),
            }
        }
    }

    impl From<ProcessIdentity> for ManagedEngineOwner {
        fn from(identity: ProcessIdentity) -> Self {
            Self {
                pid: identity.pid,
                start_fingerprint: identity.start_fingerprint,
                executable: identity.executable,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OwnershipRecord {
        schema_version: u32,
        owner: ProcessIdentity,
        engine: ProcessIdentity,
        process_group: u32,
    }

    /// Explicit-directory durable ownership store.
    ///
    /// This type never reads environment variables or selects a product-specific
    /// default. Its caller is responsible for choosing the state directory.
    #[derive(Debug, Clone)]
    pub struct ProcessOwnershipStore {
        directory: PathBuf,
    }

    #[derive(Debug)]
    pub(crate) struct OpenDirectory {
        file: std::fs::File,
    }

    #[derive(Debug)]
    pub(crate) struct StoredOwnership {
        directory: Arc<OpenDirectory>,
        name: OsString,
        record: OwnershipRecord,
    }

    impl ProcessOwnershipStore {
        /// Construct a store for one explicit state directory.
        pub fn at(directory: impl Into<PathBuf>) -> Self {
            Self {
                directory: directory.into(),
            }
        }

        /// Create or validate the private state directory without writing a record.
        pub fn ensure_private_directory(&self) -> Result<(), EngineDriverError> {
            OpenDirectory::open(&self.directory, true)?.ok_or_else(|| {
                ownership_error(
                    "create managed-engine ownership directory",
                    "directory remained absent after creation",
                )
            })?;
            Ok(())
        }

        pub(crate) fn open_or_create(&self) -> Result<Arc<OpenDirectory>, EngineDriverError> {
            OpenDirectory::open(&self.directory, true)?
                .map(Arc::new)
                .ok_or_else(|| {
                    ownership_error(
                        "create managed-engine ownership directory",
                        "directory remained absent after creation",
                    )
                })
        }

        pub(crate) fn persist_current_engine_in(
            &self,
            directory: Arc<OpenDirectory>,
            engine_pid: u32,
            process_group: u32,
            executable: &Path,
        ) -> Result<StoredOwnership, EngineDriverError> {
            let owner = process_identity(std::process::id()).ok_or_else(|| {
                ownership_error(
                    "capture managed-engine owner",
                    "exact owner process identity is unavailable",
                )
            })?;
            let mut engine = process_identity(engine_pid).ok_or_else(|| {
                ownership_error(
                    "capture managed-engine process",
                    "exact engine process identity is unavailable",
                )
            })?;
            if process_group_for(engine_pid) != Some(process_group) {
                return Err(ownership_error(
                    "capture managed-engine process",
                    "engine is not the exact leader of its isolated process group",
                ));
            }
            engine.executable = Some(executable.to_path_buf());
            self.persist_in(
                directory,
                OwnershipRecord {
                    schema_version: SCHEMA_VERSION,
                    owner,
                    engine,
                    process_group,
                },
            )
        }

        fn persist_in(
            &self,
            directory: Arc<OpenDirectory>,
            record: OwnershipRecord,
        ) -> Result<StoredOwnership, EngineDriverError> {
            if record.schema_version != SCHEMA_VERSION
                || record.engine.pid == 0
                || record.process_group != record.engine.pid
            {
                return Err(ownership_error(
                    "persist managed-engine ownership",
                    "record identity or process group is invalid",
                ));
            }
            if directory.record_names()?.len() >= MAX_RECORDS {
                return Err(ownership_error(
                    "persist managed-engine ownership",
                    "record limit was reached",
                ));
            }
            let name = OsString::from(format!(
                "{}-{}.json",
                record.engine.pid, record.engine.start_fingerprint
            ));
            let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let temporary = OsString::from(format!(
                ".{}-{}-{sequence}-{nonce}.tmp",
                record.engine.pid,
                std::process::id()
            ));
            let bytes = serde_json::to_vec(&record).map_err(|error| {
                ownership_error("encode managed-engine ownership", error.to_string())
            })?;
            if bytes.len() > MAX_RECORD_BYTES {
                return Err(ownership_error(
                    "encode managed-engine ownership",
                    "record exceeds the bounded record size",
                ));
            }
            let mut file = directory.create_record(&temporary)?;
            let write_result = (|| -> std::io::Result<()> {
                file.write_all(&bytes)?;
                file.sync_all()?;
                directory.rename(&temporary, &name)?;
                directory.sync()?;
                Ok(())
            })();
            if let Err(error) = write_result {
                let _ = directory.unlink(&temporary);
                return Err(ownership_error(
                    "atomically persist managed-engine ownership",
                    error.to_string(),
                ));
            }
            Ok(StoredOwnership {
                directory,
                name,
                record,
            })
        }

        fn records(&self) -> Result<Vec<StoredOwnership>, EngineDriverError> {
            let Some(directory) = OpenDirectory::open(&self.directory, false)?.map(Arc::new) else {
                return Ok(Vec::new());
            };
            directory
                .record_names()?
                .into_iter()
                .map(|name| {
                    let record = directory.read_record(&name)?;
                    Ok(StoredOwnership {
                        directory: Arc::clone(&directory),
                        name,
                        record,
                    })
                })
                .collect()
        }

        fn reap_stale(&self, grace: Duration) -> Result<usize, EngineDriverError> {
            let mut reaped = 0;
            for ownership in self.records()? {
                let owner = &ownership.record.owner;
                if process_identity(owner.pid)
                    .as_ref()
                    .is_some_and(|actual| identity_matches(owner, actual))
                {
                    continue;
                }
                reaped += usize::from(reap_stored(&ownership, grace)?);
            }
            Ok(reaped)
        }

        fn reap_owned_by_identity(
            &self,
            owner: &ManagedEngineOwner,
            owner_exit_timeout: Duration,
            engine_grace: Duration,
        ) -> Result<usize, EngineDriverError> {
            let owner_identity = owner.identity();
            if !wait_for_identity_change(&owner_identity, owner_exit_timeout) {
                return Err(ownership_error(
                    format!("wait for managed-engine owner pid {}", owner.pid),
                    "owner retained its recorded start fingerprint",
                ));
            }
            let mut reaped = 0;
            for ownership in self
                .records()?
                .into_iter()
                .filter(|entry| identity_matches(&owner_identity, &entry.record.owner))
            {
                reaped += usize::from(reap_stored(&ownership, engine_grace)?);
            }
            Ok(reaped)
        }

        fn reap_owned_by_pid(
            &self,
            owner_pid: u32,
            owner_exit_timeout: Duration,
            engine_grace: Duration,
        ) -> Result<usize, EngineDriverError> {
            let records = self.records()?;
            let mut owners = records
                .iter()
                .filter(|entry| entry.record.owner.pid == owner_pid)
                .map(|entry| entry.record.owner.clone())
                .collect::<Vec<_>>();
            owners.sort_by_key(|owner| owner.start_fingerprint);
            owners.dedup_by_key(|owner| owner.start_fingerprint);
            if owners.len() > 1 {
                return Err(ownership_error(
                    "resolve managed-engine owner PID",
                    "multiple recorded generations use this PID",
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
    }

    impl OpenDirectory {
        fn open(path: &Path, create: bool) -> Result<Option<Self>, EngineDriverError> {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|error| ownership_error("resolve ownership directory", error))?
                    .join(path)
            };
            #[cfg(target_os = "macos")]
            let absolute = normalize_macos_root_alias(absolute);
            let mut components = Vec::new();
            for component in absolute.components() {
                match component {
                    std::path::Component::RootDir | std::path::Component::CurDir => {}
                    std::path::Component::Normal(name) => components.push(name.to_os_string()),
                    _ => {
                        return Err(ownership_error(
                            "validate ownership directory",
                            "path must be absolute and contain no parent traversal",
                        ));
                    }
                }
            }
            let name = components.pop().ok_or_else(|| {
                ownership_error(
                    "validate ownership directory",
                    "filesystem root cannot be an ownership directory",
                )
            })?;
            let root = CString::new("/").map_err(|error| ownership_error("open root", error))?;
            let root_fd = unsafe {
                libc::open(
                    root.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if root_fd < 0 {
                return Err(ownership_error(
                    "open ownership path root",
                    std::io::Error::last_os_error(),
                ));
            }
            let mut parent = unsafe { std::fs::File::from_raw_fd(root_fd) };
            for component in components {
                validate_parent(&parent)?;
                let component_c = component_name(&component)?;
                let mut fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        component_c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    )
                };
                if fd < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::NotFound && create {
                        if unsafe { libc::mkdirat(parent.as_raw_fd(), component_c.as_ptr(), 0o700) }
                            != 0
                        {
                            let create_error = std::io::Error::last_os_error();
                            if create_error.kind() != std::io::ErrorKind::AlreadyExists {
                                return Err(ownership_error(
                                    "create ownership path ancestor",
                                    create_error,
                                ));
                            }
                        }
                        fd = unsafe {
                            libc::openat(
                                parent.as_raw_fd(),
                                component_c.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_DIRECTORY
                                    | libc::O_CLOEXEC
                                    | libc::O_NOFOLLOW,
                            )
                        };
                    } else if error.kind() == std::io::ErrorKind::NotFound {
                        return Ok(None);
                    } else {
                        return Err(ownership_error("open ownership path ancestor", error));
                    }
                }
                if fd < 0 {
                    return Err(ownership_error(
                        "open ownership path ancestor",
                        std::io::Error::last_os_error(),
                    ));
                }
                parent = unsafe { std::fs::File::from_raw_fd(fd) };
            }
            validate_parent(&parent)?;
            let name_c = component_name(&name)?;
            if create && unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(ownership_error("create ownership directory", error));
                }
            }
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if !create && error.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(ownership_error("open ownership directory", error));
            }
            let directory = Self {
                file: unsafe { std::fs::File::from_raw_fd(fd) },
            };
            directory.validate()?;
            Ok(Some(directory))
        }

        fn validate(&self) -> Result<(), EngineDriverError> {
            let metadata = descriptor_stat(self.file.as_raw_fd())
                .map_err(|error| ownership_error("inspect ownership directory", error))?;
            if metadata.st_uid != unsafe { libc::geteuid() } {
                return Err(ownership_error(
                    "validate ownership directory",
                    "directory must be owned by the effective user",
                ));
            }
            // Pre-hardening binaries created this directory with an owner-only
            // 0755 mode. Tighten that legacy state on both spawn and recovery
            // opens, while continuing to reject group- or world-writable state.
            let mut mode = metadata.st_mode & 0o777;
            if mode != 0o700 && mode & 0o022 == 0 {
                if unsafe { libc::fchmod(self.file.as_raw_fd(), 0o700) } != 0 {
                    return Err(ownership_error(
                        "tighten managed-engine ownership directory",
                        std::io::Error::last_os_error(),
                    ));
                }
                mode = 0o700;
            }
            if mode != 0o700 {
                return Err(ownership_error(
                    "validate ownership directory",
                    "directory must have mode 0700",
                ));
            }
            Ok(())
        }

        fn create_record(&self, name: &OsStr) -> Result<std::fs::File, EngineDriverError> {
            let name = component_name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(ownership_error(
                    "create ownership record",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }

        fn read_record(&self, name: &OsStr) -> Result<OwnershipRecord, EngineDriverError> {
            let name_c = component_name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(ownership_error(
                    "read ownership record",
                    std::io::Error::last_os_error(),
                ));
            }
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = descriptor_stat(file.as_raw_fd())
                .map_err(|error| ownership_error("inspect ownership record", error))?;
            if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
                || metadata.st_uid != unsafe { libc::geteuid() }
                || metadata.st_mode & 0o077 != 0
                || metadata.st_size < 0
                || u64::try_from(metadata.st_size).unwrap_or(u64::MAX) > MAX_RECORD_BYTES as u64
            {
                return Err(ownership_error(
                    "validate ownership record",
                    "record must be a bounded private regular file",
                ));
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take((MAX_RECORD_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|error| ownership_error("read ownership record", error))?;
            if bytes.len() > MAX_RECORD_BYTES {
                return Err(ownership_error(
                    "validate ownership record",
                    "record is too large",
                ));
            }
            let record: OwnershipRecord = serde_json::from_slice(&bytes)
                .map_err(|error| ownership_error("parse ownership record", error))?;
            if record.schema_version != SCHEMA_VERSION
                || record.engine.pid == 0
                || record.process_group != record.engine.pid
            {
                return Err(ownership_error(
                    "validate ownership record",
                    "unsafe record identity",
                ));
            }
            Ok(record)
        }

        fn record_names(&self) -> Result<Vec<OsString>, EngineDriverError> {
            let duplicate = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                return Err(ownership_error(
                    "duplicate ownership directory",
                    std::io::Error::last_os_error(),
                ));
            }
            let stream = unsafe { libc::fdopendir(duplicate) };
            if stream.is_null() {
                unsafe { libc::close(duplicate) };
                return Err(ownership_error(
                    "read ownership directory",
                    std::io::Error::last_os_error(),
                ));
            }
            let stream = DirectoryStream(stream);
            let mut names = Vec::new();
            loop {
                clear_errno();
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    if std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or_default()
                        == 0
                    {
                        break;
                    }
                    return Err(ownership_error(
                        "read ownership directory",
                        std::io::Error::last_os_error(),
                    ));
                }
                let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if bytes == b"." || bytes == b".." || !bytes.ends_with(b".json") {
                    continue;
                }
                if names.len() >= MAX_RECORDS {
                    return Err(ownership_error(
                        "read ownership directory",
                        "record limit exceeded",
                    ));
                }
                names.push(OsString::from_vec(bytes.to_vec()));
            }
            names.sort();
            Ok(names)
        }

        fn rename(&self, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
            let from = io_component_name(from)?;
            let to = io_component_name(to)?;
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
            let name = io_component_name(name)?;
            if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error);
                }
            }
            Ok(())
        }

        fn sync(&self) -> std::io::Result<()> {
            self.file.sync_all()
        }

        #[cfg(target_os = "macos")]
        pub(crate) fn create_cloexec_fifo_pair(
            &self,
            label: &str,
        ) -> std::io::Result<(std::fs::File, std::fs::File)> {
            let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!(
                ".gate-{label}-{}-{sequence}.fifo",
                std::process::id()
            ));
            let name_c = io_component_name(&name)?;
            if unsafe { libc::mkfifoat(self.file.as_raw_fd(), name_c.as_ptr(), 0o600) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
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
            set_blocking(reader.as_raw_fd())?;
            set_blocking(writer.as_raw_fd())?;
            Ok((reader, writer))
        }
    }

    #[cfg(target_os = "macos")]
    fn set_blocking(fd: libc::c_int) -> std::io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    impl StoredOwnership {
        pub(crate) fn exact_engine_owns_group(&self) -> bool {
            process_identity(self.record.engine.pid)
                .as_ref()
                .is_some_and(|actual| identity_matches(&self.record.engine, actual))
                && process_group_for(self.record.engine.pid) == Some(self.record.process_group)
        }

        pub(crate) fn signal_if_exact(&self, signal: i32) -> Result<(), EngineDriverError> {
            if self.exact_engine_owns_group() {
                signal_group(self.record.process_group, signal);
                return Ok(());
            }
            if !process_group_exists(self.record.process_group) {
                return Ok(());
            }
            Err(ownership_error(
                "signal managed-engine process group",
                "occupied group does not match the exact engine generation",
            ))
        }

        pub(crate) fn clear_after_exit(&self) -> Result<(), EngineDriverError> {
            if process_identity(self.record.engine.pid)
                .as_ref()
                .is_some_and(|actual| identity_matches(&self.record.engine, actual))
                || process_group_exists(self.record.process_group)
            {
                return Err(ownership_error(
                    "clear managed-engine ownership",
                    "exact engine or a process-group descendant is still alive",
                ));
            }
            self.directory
                .unlink(&self.name)
                .and_then(|()| self.directory.sync())
                .map_err(|error| ownership_error("clear managed-engine ownership", error))
        }
    }

    fn reap_stored(
        ownership: &StoredOwnership,
        grace: Duration,
    ) -> Result<bool, EngineDriverError> {
        let record = &ownership.record;
        match process_identity(record.engine.pid) {
            Some(actual)
                if identity_matches(&record.engine, &actual)
                    && process_group_for(record.engine.pid) == Some(record.process_group) => {}
            Some(_) | None if !process_group_exists(record.process_group) => {
                ownership.clear_after_exit()?;
                return Ok(false);
            }
            _ => {
                return Err(ownership_error(
                    "reap managed-engine process group",
                    "occupied group does not match the exact engine generation",
                ));
            }
        }
        ownership.signal_if_exact(libc::SIGTERM)?;
        if !wait_for_group_exit(record.process_group, grace) {
            ownership.signal_if_exact(libc::SIGKILL)?;
            if !wait_for_group_exit(record.process_group, Duration::from_secs(5)) {
                return Err(ownership_error(
                    "reap managed-engine process group",
                    "exact process group remained alive after forced termination",
                ));
            }
        }
        ownership.clear_after_exit()?;
        Ok(true)
    }

    /// Capture the exact generation for one live native process.
    pub fn capture_managed_engine_owner(pid: u32) -> Option<ManagedEngineOwner> {
        process_identity(pid).map(ManagedEngineOwner::from)
    }

    pub(crate) fn capture_process_group_leader(pid: u32) -> Option<ManagedEngineOwner> {
        process_identity(pid)
            .filter(|identity| process_group_for(identity.pid) == Some(identity.pid))
            .map(ManagedEngineOwner::from)
    }

    pub(crate) fn owner_still_leads_process_group(owner: &ManagedEngineOwner) -> bool {
        process_identity(owner.pid)
            .as_ref()
            .is_some_and(|actual| identity_matches(&owner.identity(), actual))
            && process_group_for(owner.pid) == Some(owner.pid)
    }

    /// Reap exact engines whose recorded owner generation is no longer live.
    pub fn reap_stale_managed_engines_at(
        directory: &Path,
        grace: Duration,
    ) -> Result<usize, EngineDriverError> {
        ProcessOwnershipStore::at(directory).reap_stale(grace)
    }

    /// Wait for one exact owner generation to exit, then reap only its engines.
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

    /// Resolve one recorded owner generation by PID, wait for its exit, and reap it.
    pub fn reap_managed_engines_owned_by_at(
        directory: &Path,
        owner_pid: u32,
        owner_exit_timeout: Duration,
        engine_grace: Duration,
    ) -> Result<usize, EngineDriverError> {
        ProcessOwnershipStore::at(directory).reap_owned_by_pid(
            owner_pid,
            owner_exit_timeout,
            engine_grace,
        )
    }

    fn ownership_error(
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

    fn component_name(name: &OsStr) -> Result<CString, EngineDriverError> {
        io_component_name(name).map_err(|error| ownership_error("validate path component", error))
    }

    fn io_component_name(name: &OsStr) -> std::io::Result<CString> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid path component",
            ));
        }
        CString::new(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path component contains NUL",
            )
        })
    }

    fn validate_parent(parent: &std::fs::File) -> Result<(), EngineDriverError> {
        let metadata = descriptor_stat(parent.as_raw_fd())
            .map_err(|error| ownership_error("inspect ownership parent", error))?;
        let mode = metadata.st_mode;
        if mode & libc::S_IFMT != libc::S_IFDIR || (mode & 0o022 != 0 && mode & libc::S_ISVTX == 0)
        {
            return Err(ownership_error(
                "validate ownership parent",
                "parent is writable by other users without the sticky bit",
            ));
        }
        Ok(())
    }

    fn descriptor_stat(fd: libc::c_int) -> std::io::Result<libc::stat> {
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(metadata)
    }

    #[cfg(target_os = "linux")]
    fn clear_errno() {
        unsafe { *libc::__errno_location() = 0 };
    }

    #[cfg(target_os = "macos")]
    fn clear_errno() {
        unsafe { *libc::__error() = 0 };
    }

    struct DirectoryStream(*mut libc::DIR);

    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }

    #[cfg(target_os = "macos")]
    fn normalize_macos_root_alias(path: PathBuf) -> PathBuf {
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

    fn identity_matches(expected: &ProcessIdentity, actual: &ProcessIdentity) -> bool {
        expected.pid == actual.pid && expected.start_fingerprint == actual.start_fingerprint
    }

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

    pub(crate) fn process_group_exists(group: u32) -> bool {
        let group = match i32::try_from(group) {
            Ok(group) if group > 0 => group,
            _ => return false,
        };
        let result = unsafe { libc::kill(-group, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    fn process_group_for(pid: u32) -> Option<u32> {
        let pid = i32::try_from(pid).ok()?;
        let group = unsafe { libc::getpgid(pid) };
        u32::try_from(group).ok().filter(|group| *group > 0)
    }

    pub(crate) fn signal_group(group: u32, signal: i32) {
        if let Ok(group) = i32::try_from(group) {
            if group > 0 {
                unsafe { libc::kill(-group, signal) };
            }
        }
    }

    pub(crate) fn wait_for_group_exit(group: u32, duration: Duration) -> bool {
        let deadline = std::time::Instant::now() + duration;
        loop {
            reap_group_children(group);
            if !process_group_exists(group) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn reap_group_children(group: u32) {
        let Ok(group) = i32::try_from(group) else {
            return;
        };
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(-group, &mut status, libc::WNOHANG) };
            if waited > 0 {
                continue;
            }
            if waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
    }

    #[cfg(target_os = "linux")]
    fn process_identity(pid: u32) -> Option<ProcessIdentity> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_name = stat.rsplit_once(") ")?.1;
        let fields = after_name.split_whitespace().collect::<Vec<_>>();
        if fields.first().copied() == Some("Z") {
            return None;
        }
        Some(ProcessIdentity {
            pid,
            start_fingerprint: fields.get(19)?.parse().ok()?,
            executable: std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
        })
    }

    #[cfg(target_os = "macos")]
    fn process_identity(pid: u32) -> Option<ProcessIdentity> {
        use std::mem::{size_of, MaybeUninit};

        const PROC_PIDTBSDINFO: i32 = 3;
        const PROC_PIDPATHINFO_MAXSIZE: usize = 4_096;
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
        let mut info = MaybeUninit::<ProcBsdInfo>::zeroed();
        let expected = size_of::<ProcBsdInfo>();
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
        let mut path = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
        let length = unsafe {
            proc_pidpath(
                i32::try_from(pid).ok()?,
                path.as_mut_ptr().cast(),
                u32::try_from(path.len()).ok()?,
            )
        };
        let executable = usize::try_from(length)
            .ok()
            .filter(|length| *length > 0 && *length <= path.len())
            .map(|length| {
                path.truncate(length);
                PathBuf::from(OsString::from_vec(path))
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
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use native::{
    capture_managed_engine_owner, reap_managed_engines_owned_by_at,
    reap_managed_engines_owned_by_identity_at, reap_stale_managed_engines_at, ManagedEngineOwner,
    ProcessOwnershipStore,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use native::{
    capture_process_group_leader, owner_still_leads_process_group, process_group_exists,
    signal_group, wait_for_group_exit, OpenDirectory, StoredOwnership,
};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use sb_runtime_core::{EngineDriverError, EngineFailureReason};
    use serde::{Deserialize, Serialize};

    /// Exact owner tokens are unavailable without native start fingerprints.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ManagedEngineOwner;

    impl ManagedEngineOwner {
        /// Empty platform tokens never confer cleanup authority.
        pub fn same_process_generation(&self, _other: &Self) -> bool {
            false
        }
    }

    /// Explicit ownership directory retained for portable API construction.
    #[derive(Debug, Clone)]
    pub struct ProcessOwnershipStore {
        _directory: PathBuf,
    }

    impl ProcessOwnershipStore {
        /// Construct a store for an explicit state directory.
        pub fn at(directory: impl Into<PathBuf>) -> Self {
            Self {
                _directory: directory.into(),
            }
        }

        /// Refuse durable ownership on a platform without exact identities.
        pub fn ensure_private_directory(&self) -> Result<(), EngineDriverError> {
            Err(unsupported_error())
        }
    }

    /// Exact owner capture is unavailable on this platform.
    pub fn capture_managed_engine_owner(_pid: u32) -> Option<ManagedEngineOwner> {
        None
    }

    /// Durable stale recovery is unavailable on this platform.
    pub fn reap_stale_managed_engines_at(
        _directory: &Path,
        _grace: Duration,
    ) -> Result<usize, EngineDriverError> {
        Ok(0)
    }

    /// Exact-owner durable recovery is unavailable on this platform.
    pub fn reap_managed_engines_owned_by_identity_at(
        _directory: &Path,
        _owner: &ManagedEngineOwner,
        _owner_exit_timeout: Duration,
        _engine_grace: Duration,
    ) -> Result<usize, EngineDriverError> {
        Ok(0)
    }

    /// PID-scoped durable recovery is unavailable on this platform.
    pub fn reap_managed_engines_owned_by_at(
        _directory: &Path,
        _owner_pid: u32,
        _owner_exit_timeout: Duration,
        _engine_grace: Duration,
    ) -> Result<usize, EngineDriverError> {
        Ok(0)
    }

    fn unsupported_error() -> EngineDriverError {
        EngineDriverError::new(
            EngineFailureReason::EngineSpawnFailed,
            "native durable process ownership is unavailable on this platform",
            "use a supported native process host",
            false,
        )
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use unsupported::{
    capture_managed_engine_owner, reap_managed_engines_owned_by_at,
    reap_managed_engines_owned_by_identity_at, reap_stale_managed_engines_at, ManagedEngineOwner,
    ProcessOwnershipStore,
};
