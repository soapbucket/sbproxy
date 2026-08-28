//! Owner-only creation of the durable files SBproxy writes (WOR-2626).
//!
//! # Why this module exists
//!
//! Every durable sink in the workspace writes something an attacker on
//! the same host would like to read: the signed usage ledger, the
//! settlement database, per-request event lines, session ledger
//! records, the LLM usage feed. Each one used to open its file with a
//! bare [`std::fs::OpenOptions`], which asks the kernel for `0o666` and
//! lets the process umask decide the rest. The near-universal default
//! umask is `0o022`, so all of those files landed on disk as `0o644`:
//! readable by every account on the box, including the one an
//! unrelated compromised service runs as.
//!
//! # The contract
//!
//! Every function here guarantees the same two properties for a file
//! SBproxy owns:
//!
//! 1. **No window.** The mode is an argument to `open(2)` itself, via
//!    [`std::os::unix::fs::OpenOptionsExt::mode`], so a file this
//!    process creates has never existed at a wider mode. A
//!    create-then-`chmod` would leave the file world-readable for the
//!    microseconds in between, which is long enough on a busy host for
//!    another process to open a descriptor and keep reading through
//!    the tightening.
//! 2. **No inheritance.** After the open, the mode is set again through
//!    the descriptor. That second step covers a file that already
//!    existed at a looser mode: reopening a `0o644` ledger left by an
//!    older build, or one an attacker pre-created to be readable. If
//!    the tightening cannot be done, the call fails rather than
//!    returning a handle to a file other accounts can read.
//!
//! The second step goes through the open descriptor
//! ([`std::fs::File::set_permissions`], which is `fchmod`) and never
//! through the path. A path-based `chmod` follows symlinks, so a
//! pre-created `events.ndjson -> /etc/shadow` would have this process
//! change the mode of a file it never meant to touch. `fchmod` acts on
//! exactly the inode that was opened.
//!
//! # What is deliberately not touched
//!
//! **Directories that already exist.** Sink paths are operator
//! configuration. `/var/log/sbproxy/events.ndjson` may sit in a
//! directory the operator created, shares with a log shipper, and
//! expects to stay `0o755`. This module sets `0o700` on directories it
//! creates and leaves every directory it finds alone. A `0o600` file
//! inside a `0o755` directory still leaks its name, its size, and its
//! existence, and a ledger filename can carry a tenant, so an operator
//! who cares should own the directory mode; the reference deployments
//! in `docs/` do.
//!
//! **Anything that is not a regular file.** A path may point at
//! `/dev/stdout`, at a fifo drained by a shipper, or at a device. Those
//! have a mode the operator chose on purpose and that this process
//! usually cannot change, so the tightening step is skipped for them.
//! It is not silent: the skip is on file *type*, checked through the
//! descriptor with `fstat`, and only the modes of regular files are
//! this crate's business.
//!
//! # Platforms without POSIX modes
//!
//! Windows has no permission bits to set. Rather than a `#[cfg]` that
//! quietly does nothing, the behavior is named: files and directories
//! inherit the containing directory's ACL, no mode is applied, and
//! [`enforcement`] reports [`ModeEnforcement::InheritedAcl`] so an
//! operator-facing surface can say so instead of implying a protection
//! that is not there. Synthesizing an owner-only DACL is a real
//! feature with real ways to be half right, and a half-right ACL is
//! worse than a documented gap.

use std::fs::File;
use std::io;
use std::path::Path;

/// The mode every SBproxy-owned file is created at and held at: read
/// and write for the owning user, nothing for group or other.
const OWNER_ONLY_FILE_MODE: u32 = 0o600;

/// The mode every directory SBproxy creates for its own state is
/// created at. Traversal as well as read is withheld, because a
/// directory a stranger can `stat` through still discloses the names
/// and sizes of the files inside it.
const OWNER_ONLY_DIR_MODE: u32 = 0o700;

/// How much this build can actually enforce, so a caller reporting to
/// an operator can be accurate on every platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeEnforcement {
    /// POSIX permission bits are set at creation and reasserted
    /// through the descriptor afterwards.
    Posix {
        /// The mode applied to every file this module opens.
        file_mode: u32,
        /// The mode applied to every directory this module creates.
        dir_mode: u32,
    },
    /// The target has no POSIX permission bits. Files and directories
    /// inherit the containing directory's ACL and no mode is applied.
    InheritedAcl,
}

/// Reports what the running build enforces. Constant per target, not
/// per call.
///
/// ```
/// use sbproxy_util::secure_fs::{enforcement, ModeEnforcement};
/// match enforcement() {
///     ModeEnforcement::Posix { file_mode, .. } => assert_eq!(file_mode, 0o600),
///     ModeEnforcement::InheritedAcl => {}
/// }
/// ```
#[must_use]
pub const fn enforcement() -> ModeEnforcement {
    if cfg!(unix) {
        ModeEnforcement::Posix {
            file_mode: OWNER_ONLY_FILE_MODE,
            dir_mode: OWNER_ONLY_DIR_MODE,
        }
    } else {
        ModeEnforcement::InheritedAcl
    }
}

/// Opens `path` for appending, creating it owner-only if it is absent
/// and tightening it if it already exists at a looser mode.
///
/// This is the opener for every append-structured durable sink: the
/// usage ledger, the request event file, the session ledger, the JSONL
/// usage feed.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when the file cannot be opened,
/// and an error when an existing regular file cannot be tightened to
/// `0o600`. The second case is a refusal on purpose: a sink that cannot
/// make its own output owner-only should say so at startup rather than
/// append secrets to a file other accounts read.
pub fn open_append_owner_only(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    open_with_mode(options, path)
}

/// Makes sure `path` exists as an owner-only file and closes it again,
/// without truncating or writing anything.
///
/// This exists for the one caller that cannot own the open: SQLite
/// opens the settlement database itself. Creating the database file at
/// `0o600` first means the `-wal` and `-shm` sidecars land at `0o600`
/// too, because SQLite copies the main database's mode onto them.
///
/// # Errors
///
/// As [`open_append_owner_only`].
pub fn ensure_file_owner_only(path: &Path) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    // Deliberately not `truncate`: this may be an existing database.
    options.create(true).write(true);
    open_with_mode(options, path).map(drop)
}

/// Creates `path` owner-only, truncating whatever was there.
///
/// The opener for a sink that writes a whole file in one pass instead
/// of appending to it: the gzip of a rotated access log. Appending
/// would be wrong there rather than merely untidy, because a partial
/// `.gz` left by a rotation that died mid-write is not a prefix of the
/// member this call is about to write, and the reader would see one
/// corrupt stream instead of one truncated one.
///
/// # Errors
///
/// As [`open_append_owner_only`].
pub fn create_truncate_owner_only(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    open_with_mode(options, path)
}

/// Tightens a file that is already on disk, and does nothing when it
/// is not there.
///
/// The opener for a file this process did not write and will not
/// write: a rotated backup left by an older build, an archive moved
/// into place by `rename(2)`. Unlike [`ensure_file_owner_only`] it
/// never creates, because a sweep that creates is a sweep that
/// resurrects a file somebody just deleted.
///
/// A path that does not exist is `Ok(())`. Every other failure is
/// reported, because a backup that cannot be tightened is a backup
/// other accounts can still read.
///
/// # Errors
///
/// As [`open_append_owner_only`], minus the not-found case.
pub fn tighten_existing_owner_only(path: &Path) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    // Read-only and no `create`: this call is a chmod through a
    // descriptor, not an open of something to write.
    options.read(true);
    match open_with_mode(options, path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Creates `path` and every missing parent, each at `0o700`.
///
/// Directories that already exist are left exactly as they are, mode
/// included. See the module documentation for why: an operator's
/// `/var/log` is not this process's to narrow.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when a component cannot be
/// created.
pub fn create_dir_all_owner_only(path: &Path) -> io::Result<()> {
    create_dir_all_inner(path)
}

/// `mkdir(2)` each missing component with the mode already set.
#[cfg(unix)]
fn create_dir_all_inner(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    // `recursive` applies the builder's mode to every component it
    // creates, and creates nothing for a component that is already
    // there, which is exactly the split this module wants.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(OWNER_ONLY_DIR_MODE)
        .create(path)
}

/// No POSIX mode to request. See [`ModeEnforcement::InheritedAcl`].
#[cfg(not(unix))]
fn create_dir_all_inner(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Sets `0o600` on an already-open regular file.
///
/// Takes the descriptor rather than a path, which is what makes it
/// safe: `fchmod` cannot be redirected through a symlink the way a
/// path-based `chmod` can. There is no path-taking variant for exactly
/// that reason.
///
/// A handle that is not a regular file (a fifo, a device, a socket) is
/// left alone and `Ok(())` is returned.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when the file's type cannot be
/// read or the mode cannot be set.
#[cfg(unix)]
fn tighten_to_owner_only(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = file.metadata()?;
    // A fifo or a device has a mode the operator chose and that this
    // process generally may not change. Only regular files are ours.
    if !metadata.is_file() {
        return Ok(());
    }
    if metadata.permissions().mode() & 0o7777 == OWNER_ONLY_FILE_MODE {
        return Ok(());
    }
    file.set_permissions(std::fs::Permissions::from_mode(OWNER_ONLY_FILE_MODE))
}

/// No POSIX mode to reassert. See [`ModeEnforcement::InheritedAcl`].
#[cfg(not(unix))]
fn tighten_to_owner_only(_file: &File) -> io::Result<()> {
    Ok(())
}

/// The shared body of both openers: request the mode in the open,
/// then reassert it through the descriptor.
///
/// Both halves are needed and neither is redundant. The first covers a
/// file this call creates, so it never exists at a wider mode. The
/// second covers a file that was already there, and also covers a
/// hostile or merely odd umask: `open(2)` masks the requested mode, so
/// a umask of `0o200` would otherwise yield an unwritable `0o400`
/// ledger. `fchmod` is not masked.
fn open_with_mode(mut options: std::fs::OpenOptions, path: &Path) -> io::Result<File> {
    apply_creation_mode(&mut options);
    let file = options.open(path)?;
    tighten_to_owner_only(&file).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot make '{}' owner-only ({OWNER_ONLY_FILE_MODE:04o}): {error}",
                path.display()
            ),
        )
    })?;
    Ok(file)
}

/// Puts `0o600` into the `open(2)` call itself. This is the half that
/// closes the window; see the module documentation.
#[cfg(unix)]
fn apply_creation_mode(options: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(OWNER_ONLY_FILE_MODE);
}

/// No POSIX mode to request. See [`ModeEnforcement::InheritedAcl`].
#[cfg(not(unix))]
fn apply_creation_mode(_options: &mut std::fs::OpenOptions) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("stat the path under test")
            .permissions()
            .mode()
            & 0o7777
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sbproxy-secure-fs-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    /// The creation half. `0o600` exactly, whatever the ambient umask
    /// is: a umask can only clear bits from the mode passed to
    /// `open(2)`, and the reassertion puts back anything it cleared.
    ///
    /// On a runner whose umask is already `0o077` this would also pass
    /// against the old bare `OpenOptions`, so it is not on its own a
    /// red-before-the-fix test. `a_pre_existing_world_readable_file_is_tightened`
    /// is the umask-independent half.
    #[test]
    fn a_created_file_is_owner_only() {
        let dir = scratch("created");
        let path = dir.join("ledger.ndjson");
        let file = open_append_owner_only(&path).expect("create the file");
        assert_eq!(mode_of(&path), OWNER_ONLY_FILE_MODE);
        drop(file);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The inheritance half. A file that already exists at `0o644` is
    /// tightened on open, which the creation mode alone cannot do:
    /// `OpenOptions::mode` is ignored when the file is not created.
    #[test]
    fn a_pre_existing_world_readable_file_is_tightened() {
        let dir = scratch("preexisting");
        let path = dir.join("ledger.ndjson");
        drop(std::fs::File::create(&path).expect("pre-create the file"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen the pre-created file");
        assert_eq!(mode_of(&path), 0o644);

        let file = open_append_owner_only(&path).expect("reopen the loose file");
        assert_eq!(mode_of(&path), OWNER_ONLY_FILE_MODE);
        drop(file);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Content survives the tightening. A sink that reopens its own
    /// ledger must append to it, not restart it.
    #[test]
    fn tightening_an_existing_file_does_not_truncate_it() {
        use std::io::Write as _;
        let dir = scratch("append");
        let path = dir.join("ledger.ndjson");
        std::fs::write(&path, b"first\n").expect("seed the file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("loosen the seeded file");

        let mut file = open_append_owner_only(&path).expect("reopen for append");
        file.write_all(b"second\n").expect("append");
        drop(file);

        assert_eq!(mode_of(&path), OWNER_ONLY_FILE_MODE);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "first\nsecond\n"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every missing component of the chain, not just the leaf.
    #[test]
    fn created_directories_are_owner_only_all_the_way_down() {
        let dir = scratch("dirs");
        let leaf = dir.join("state").join("payments").join("v1");
        create_dir_all_owner_only(&leaf).expect("create the chain");
        assert_eq!(mode_of(&leaf), OWNER_ONLY_DIR_MODE);
        assert_eq!(mode_of(&dir.join("state")), OWNER_ONLY_DIR_MODE);
        assert_eq!(
            mode_of(&dir.join("state").join("payments")),
            OWNER_ONLY_DIR_MODE
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The other half of the directory rule: a directory that is
    /// already there keeps the mode its operator gave it.
    #[test]
    fn an_existing_directory_keeps_its_mode() {
        let dir = scratch("existing-dir");
        let shared = dir.join("shared");
        std::fs::create_dir(&shared).expect("create the shared directory");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755))
            .expect("set the operator's mode");

        create_dir_all_owner_only(&shared).expect("no-op on an existing directory");
        assert_eq!(mode_of(&shared), 0o755);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A path pointing at something that is not a regular file is the
    /// documented way an operator streams a sink somewhere else. The
    /// tightening must not touch it and must not fail.
    #[test]
    fn a_non_regular_target_is_left_alone() {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        tighten_to_owner_only(&file).expect("skip a character device");
        let mode = std::fs::metadata("/dev/null")
            .expect("stat /dev/null")
            .permissions()
            .mode()
            & 0o7777;
        assert_ne!(
            mode, OWNER_ONLY_FILE_MODE,
            "/dev/null must not have been narrowed"
        );
    }

    /// The SQLite pre-creation path leaves an owner-only, empty,
    /// untruncated file behind.
    #[test]
    fn ensure_file_creates_owner_only_without_truncating() {
        let dir = scratch("ensure");
        let path = dir.join("settlement.sqlite3");
        std::fs::write(&path, b"not empty").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen");

        ensure_file_owner_only(&path).expect("ensure");
        assert_eq!(mode_of(&path), OWNER_ONLY_FILE_MODE);
        assert_eq!(
            std::fs::read(&path).expect("read back"),
            b"not empty".to_vec()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enforcement_names_the_modes_it_applies() {
        assert_eq!(
            enforcement(),
            ModeEnforcement::Posix {
                file_mode: 0o600,
                dir_mode: 0o700,
            }
        );
    }
}
