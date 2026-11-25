//! Moving a repeater's identity between a person's own state directory and the system service's —
//! the Windows `StateMigration`, step for step, because the guarantees are the same ones:
//!
//! - the move copies into a staging directory beside the destination, swaps it into place with the
//!   key last, and only then deletes the source, the key last again; so a directory is never left
//!   with a roster and no key, and a staging directory with a key in it is always complete;
//! - an interrupted move is finished by running it again;
//! - two different identities are never merged or overwritten: the move stops and says so.
//!
//! The caller marks the source (`moved-to-service`) so a per-user daemon there refuses to mint a
//! second identity for a machine whose owner already claimed the first.
//!
//! **Root runs this against directories other accounts control**: the sudo user's own state
//! directory on `install --system`, the person's again on `uninstall --system`, and the service
//! account's `/var/lib` directory (which a compromised daemon could have filled) both ways. A path
//! is therefore never trusted after it has been checked. Every directory is opened one component
//! at a time from the one above it with `O_NOFOLLOW`, and everything after that goes through the
//! opened descriptor ([`Dir`]): a symlink planted anywhere an account other than root can write,
//! or swapped in after a check, is refused rather than followed, so it can never make root read,
//! overwrite, delete or chown a file of its choosing. Files are opened `O_NOFOLLOW`, copied
//! through the descriptor, created `O_EXCL` with an explicit mode, and must belong to root or to
//! one of the accounts the caller names (`owners`).

use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use streetcryptid_repeater_host::SERVICE_MARKER;

pub const IDENTITY_FILE: &str = "secret.key";

/// The daemon's own transient files, which belong to whichever directory they are in.
const NOT_NODE_STATE: &[&str] = &["host.lock", SERVICE_MARKER, crate::paths::SOCKET_NAME];

pub fn is_node_state(name: &str) -> bool {
    !NOT_NODE_STATE.contains(&name) && !name.ends_with(".tmp")
}

/// A precheck only (the move decides for itself through [`Dir`]); it never follows a symlinked key.
pub fn has_identity(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(IDENTITY_FILE)).is_ok_and(|m| m.is_file())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Moved {
    /// The source held no identity: nothing to do.
    Nothing,
    /// The identity is now in the destination and gone from the source.
    Moved,
}

fn refused_link(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} is a symbolic link, and the repeater's state is never moved through one (it runs as \
         root). Replace it with the real directory or file, then try again.",
        path.display()
    )
}

fn check_owner(meta: &Metadata, owners: &[u32], shown: &Path) -> Result<()> {
    if meta.uid() != 0 && !owners.contains(&meta.uid()) {
        bail!(
            "{} belongs to uid {}, not to root or the account this move is for, so it was not \
             touched. Run it with sudo as the person whose repeater this is, or fix its owner.",
            shown.display(),
            meta.uid()
        );
    }
    Ok(())
}

/// A directory opened without following a symlink, used only through its descriptor.
pub struct Dir {
    file: File,
    /// For messages: the path it was opened by, which may no longer name it.
    shown: PathBuf,
    owners: Vec<u32>,
}

enum Child {
    Dir(Dir),
    Missing,
    Link,
}

impl Dir {
    /// `/proc/self/fd/N` is the opened directory itself, whatever its path names now, so a name
    /// joined onto it resolves that one name and nothing above it.
    fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    fn at(&self, name: impl AsRef<OsStr>) -> PathBuf {
        self.proc_path().join(name.as_ref())
    }

    /// Open `path` (absolute) one component at a time, creating what is missing (0700) when
    /// `create` is set; `None` when it is missing and `create` is not.
    ///
    /// A symlink is followed only while every directory above it belongs to root and nobody else
    /// may write to it, and the link is root's too: that is the system's own layout (Fedora
    /// Atomic's `/home -> var/home`), which no other account can change. Anywhere else it is
    /// refused.
    pub fn open(path: &Path, owners: &[u32], create: bool) -> Result<Option<Dir>> {
        Ok(Self::open_chain(path, owners, create)?.and_then(|mut chain| chain.pop()))
    }

    fn open_chain(path: &Path, owners: &[u32], create: bool) -> Result<Option<Vec<Dir>>> {
        if !path.is_absolute() {
            bail!("{} is not an absolute path", path.display());
        }
        let mut path = path.to_path_buf();
        let mut hops = 0;
        'walk: loop {
            let root = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY)
                .open("/")
                .context("opening /")?;
            let mut chain = vec![Dir {
                file: root,
                shown: PathBuf::from("/"),
                owners: owners.to_vec(),
            }];
            let mut trusted = true;
            let current = path.clone();
            let parts: Vec<Component> = current.components().collect();
            for (index, part) in parts.iter().enumerate() {
                let name = match part {
                    Component::RootDir | Component::CurDir => continue,
                    Component::Normal(name) => *name,
                    _ => bail!(
                        "{} has `..` in it; name the directory itself",
                        path.display()
                    ),
                };
                let parent = chain.last().expect("the chain starts at /");
                match parent.child(name, create)? {
                    Child::Dir(dir) => {
                        let meta = dir.file.metadata()?;
                        trusted = trusted && meta.uid() == 0 && meta.mode() & 0o022 == 0;
                        chain.push(dir);
                    }
                    Child::Missing => return Ok(None),
                    Child::Link => {
                        let link = parent.shown.join(name);
                        let root_link =
                            std::fs::symlink_metadata(parent.at(name)).is_ok_and(|m| m.uid() == 0);
                        if !(trusted && root_link) || hops >= 8 {
                            return Err(refused_link(&link));
                        }
                        // Resolved inside directories only root can change, then walked again
                        // from the top like any other path.
                        hops += 1;
                        let resolved = std::fs::canonicalize(&link)
                            .with_context(|| format!("resolving {}", link.display()))?;
                        path = parts[index + 1..]
                            .iter()
                            .fold(resolved, |path, part| path.join(part));
                        continue 'walk;
                    }
                }
            }
            return Ok(Some(chain));
        }
    }

    fn child(&self, name: &OsStr, create: bool) -> Result<Child> {
        let path = self.at(name);
        let shown = self.shown.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(Child::Link),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound && create => {
                // mkdir never follows a symlink in its last component.
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                    Err(e) => {
                        return Err(e).with_context(|| format!("creating {}", shown.display()))
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Child::Missing),
            Err(e) => return Err(e).with_context(|| format!("reading {}", shown.display())),
        }
        // O_NOFOLLOW again: what was looked at above may have been swapped for a link since.
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Ok(Child::Link),
            Err(e) => return Err(e).with_context(|| format!("opening {}", shown.display())),
        };
        check_owner(&file.metadata()?, &self.owners, &shown)?;
        Ok(Child::Dir(Dir {
            file,
            shown,
            owners: self.owners.clone(),
        }))
    }

    /// A directory inside this one; a symlink is refused.
    fn sub(&self, name: impl AsRef<OsStr>, create: bool) -> Result<Option<Dir>> {
        let name = name.as_ref();
        match self.child(name, create)? {
            Child::Dir(dir) => Ok(Some(dir)),
            Child::Missing => Ok(None),
            Child::Link => Err(refused_link(&self.shown.join(name))),
        }
    }

    fn set_mode(&self, mode: u32) -> Result<()> {
        self.file
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode of {}", self.shown.display()))
    }

    fn has_identity(&self) -> bool {
        std::fs::symlink_metadata(self.at(IDENTITY_FILE)).is_ok_and(|m| m.is_file())
    }

    /// A plain file's bytes, read through the descriptor that was checked.
    fn read(&self, name: impl AsRef<OsStr>) -> Result<Vec<u8>> {
        let shown = self.shown.join(name.as_ref());
        // O_NONBLOCK so a planted FIFO is refused below rather than hanging the install.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.at(name))
            .map_err(|e| match e.raw_os_error() {
                Some(libc::ELOOP) => refused_link(&shown),
                _ => anyhow::Error::new(e).context(format!("reading {}", shown.display())),
            })?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            bail!("{} is not a plain file", shown.display());
        }
        check_owner(&meta, &self.owners, &shown)?;
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", shown.display()))?;
        Ok(bytes)
    }

    /// A new file with exactly `mode`: `O_EXCL` fails on anything already there, a link included.
    fn create_file(&self, name: impl AsRef<OsStr>, bytes: &[u8], mode: u32) -> Result<File> {
        let shown = self.shown.join(name.as_ref());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.at(name))
            .with_context(|| format!("writing {}", shown.display()))?;
        // The umask may have narrowed it; say exactly what it is.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(file)
    }

    fn entries(&self) -> Result<Vec<(OsString, std::fs::FileType)>> {
        std::fs::read_dir(self.proc_path())
            .with_context(|| format!("listing {}", self.shown.display()))?
            .map(|entry| -> Result<(OsString, std::fs::FileType)> {
                let entry = entry?;
                // The entry's own type, never its target's.
                Ok((entry.file_name(), entry.file_type()?))
            })
            .collect()
    }

    fn rename(&self, name: impl AsRef<OsStr>, to: &Dir, to_name: impl AsRef<OsStr>) -> Result<()> {
        let name = name.as_ref();
        std::fs::rename(self.at(name), to.at(to_name))
            .with_context(|| format!("moving {}", self.shown.join(name).display()))
    }

    /// Remove an entry: a directory with everything in it (std's `remove_dir_all` does not follow
    /// links), anything else unlinked, a link included.
    fn remove(&self, name: impl AsRef<OsStr>) -> Result<()> {
        let name = name.as_ref();
        let path = self.at(name);
        let result = match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&path),
            Ok(_) => std::fs::remove_file(&path),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
        result.with_context(|| format!("removing {}", self.shown.join(name).display()))
    }

    fn sync(&self) {
        let _ = self.file.sync_all();
    }

    fn chown_tree(&self, uid: u32, gid: u32) -> Result<()> {
        std::os::unix::fs::fchown(&self.file, Some(uid), Some(gid))
            .with_context(|| format!("handing {} to its owner", self.shown.display()))?;
        for (name, kind) in self.entries()? {
            if kind.is_dir() {
                if let Some(dir) = self.sub(&name, false)? {
                    dir.chown_tree(uid, gid)?;
                }
            } else {
                // lchown: a link is handed over itself, never what it points at.
                std::os::unix::fs::lchown(self.at(&name), Some(uid), Some(gid)).with_context(
                    || format!("handing {} to its owner", self.shown.join(&name).display()),
                )?;
            }
        }
        Ok(())
    }
}

fn staging_name(destination: &OsStr) -> OsString {
    let mut name = destination.to_os_string();
    name.push(".incoming");
    name
}

#[cfg(test)]
fn staging_for(destination: &Path) -> PathBuf {
    destination.with_file_name(staging_name(destination.file_name().unwrap()))
}

/// Move node state from `source` into `destination`. `source_owners` and `destination_owners` are
/// the accounts besides root whose files each side may hold: the person's, or the service's.
pub fn move_state(
    source: &Path,
    destination: &Path,
    source_owners: &[u32],
    destination_owners: &[u32],
) -> Result<Moved> {
    let (Some(parent_path), Some(dest_name)) = (destination.parent(), destination.file_name())
    else {
        bail!("{} cannot hold a repeater", destination.display());
    };
    let parent = Dir::open(parent_path, destination_owners, true)?
        .context("creating the destination's parent")?;
    let dest = parent
        .sub(dest_name, true)?
        .context("creating the destination")?;
    dest.set_mode(0o700)?;
    let staging_name = staging_name(dest_name);
    let source_dir = Dir::open(source, source_owners, false)?;
    let conflict = || {
        anyhow::anyhow!(
            "{} and {} hold different repeater identities; neither was changed. \
             Keep the one the owner claimed and move the other aside by hand.",
            source.display(),
            destination.display()
        )
    };
    // A staging directory holding a key is a complete copy whose swap was interrupted.
    if let Some(staging) = parent.sub(&staging_name, false)? {
        if staging.has_identity() {
            if let Some(source) = source_dir.as_ref().filter(|s| s.has_identity()) {
                if !same_identity(source, &staging)? {
                    return Err(conflict());
                }
            }
            if dest.has_identity() {
                return Err(conflict());
            }
            swap(&staging, &parent, &staging_name, &dest)?;
            if let Some(source) = source_dir.as_ref().filter(|s| s.has_identity()) {
                delete_node_state(source)?;
            }
            return Ok(Moved::Moved);
        }
    }
    let Some(source) = source_dir.filter(|s| s.has_identity()) else {
        return Ok(Moved::Nothing);
    };
    if dest.has_identity() {
        // A finished move whose source was not yet deleted: same identity, finish it.
        if !same_identity(&source, &dest)? {
            return Err(conflict());
        }
        delete_node_state(&source)?;
        return Ok(Moved::Moved);
    }
    for (name, _) in dest.entries()? {
        if is_node_state(&name.to_string_lossy()) {
            bail!(
                "{} already holds repeater state without an identity; it was not changed",
                destination.display()
            );
        }
    }
    parent.remove(&staging_name)?;
    let staging = parent
        .sub(&staging_name, true)?
        .context("creating the staging directory")?;
    staging.set_mode(0o700)?;
    for (name, kind) in source.entries()? {
        let name_str = name.to_string_lossy();
        if !is_node_state(&name_str) || name_str == IDENTITY_FILE {
            continue;
        }
        if kind.is_symlink() {
            return Err(refused_link(&source.shown.join(&name)));
        }
        if kind.is_dir() {
            let from = source.sub(&name, false)?.context("a directory vanished")?;
            let to = staging.sub(&name, true)?.context("creating a directory")?;
            copy_dir(&from, &to)?;
        } else if kind.is_file() {
            staging.create_file(&name, &source.read(&name)?, 0o600)?;
        }
    }
    // The key last, so a staging directory with a key in it is always complete.
    staging.create_file(IDENTITY_FILE, &source.read(IDENTITY_FILE)?, 0o600)?;
    swap(&staging, &parent, &staging_name, &dest)?;
    delete_node_state(&source)?;
    Ok(Moved::Moved)
}

fn same_identity(a: &Dir, b: &Dir) -> Result<bool> {
    Ok(a.read(IDENTITY_FILE)? == b.read(IDENTITY_FILE)?)
}

/// Move a complete staging copy into place, the key last, then drop the staging directory.
fn swap(staging: &Dir, parent: &Dir, staging_name: &OsStr, destination: &Dir) -> Result<()> {
    for (name, _) in staging.entries()? {
        if name == IDENTITY_FILE {
            continue;
        }
        staging.rename(&name, destination, &name)?;
    }
    staging.rename(IDENTITY_FILE, destination, IDENTITY_FILE)?;
    destination.sync();
    parent.remove(staging_name)
}

fn delete_node_state(dir: &Dir) -> Result<()> {
    // Everything but the key first: a directory left with only a key is still a valid (if
    // empty) repeater, never a keyless one with a roster.
    for (name, _) in dir.entries()? {
        let name_str = name.to_string_lossy();
        if !is_node_state(&name_str) || name_str == IDENTITY_FILE {
            continue;
        }
        dir.remove(&name)?;
    }
    dir.remove(IDENTITY_FILE)?;
    dir.sync();
    Ok(())
}

fn copy_dir(from: &Dir, to: &Dir) -> Result<()> {
    to.set_mode(0o700)?;
    for (name, kind) in from.entries()? {
        if kind.is_symlink() {
            return Err(refused_link(&from.shown.join(&name)));
        }
        if kind.is_dir() {
            let inner_from = from.sub(&name, false)?.context("a directory vanished")?;
            let inner_to = to.sub(&name, true)?.context("creating a directory")?;
            copy_dir(&inner_from, &inner_to)?;
        } else if kind.is_file() {
            to.create_file(&name, &from.read(&name)?, 0o600)?;
        }
    }
    Ok(())
}

/// The person's own directory (for the person, never as root): created 0700.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Hand a directory and everything in it to `uid:gid` (the service account, or the person a
/// state directory is moved back to). `owners` as for [`move_state`].
pub fn chown_tree(dir: &Path, owners: &[u32], uid: u32, gid: u32) -> Result<()> {
    Dir::open(dir, owners, false)?
        .with_context(|| format!("{} is missing", dir.display()))?
        .chown_tree(uid, gid)
}

/// Give a state directory moved back to a person to them, with the directories root created on
/// the way down to it from their home.
pub fn hand_over(dir: &Path, home: &Path, uid: u32, gid: u32) -> Result<()> {
    let chain = Dir::open_chain(dir, &[uid], false)?
        .with_context(|| format!("{} is missing", dir.display()))?;
    let home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let (last, above) = chain.split_last().expect("the chain starts at /");
    for step in above {
        if step.shown.starts_with(&home)
            && step.shown != home
            && step.file.metadata().is_ok_and(|m| m.uid() == 0)
        {
            let _ = std::os::unix::fs::fchown(&step.file, Some(uid), Some(gid));
        }
    }
    last.chown_tree(uid, gid)
}

/// Write the `moved-to-service` marker into the person's directory, as theirs.
pub fn mark_moved(dir: &Path, owners: &[u32], contents: &str) -> Result<()> {
    let dir =
        Dir::open(dir, owners, false)?.with_context(|| format!("{} is missing", dir.display()))?;
    let staging = format!("{SERVICE_MARKER}.tmp");
    dir.remove(&staging)?;
    let file = dir.create_file(&staging, contents.as_bytes(), 0o644)?;
    let meta = dir.file.metadata()?;
    std::os::unix::fs::fchown(&file, Some(meta.uid()), Some(meta.gid()))?;
    dir.rename(&staging, &dir, SERVICE_MARKER)
}

/// Remove the `moved-to-service` marker from a directory the identity came back to.
pub fn clear_marker(dir: &Path, owners: &[u32]) -> Result<()> {
    match Dir::open(dir, owners, false)? {
        Some(dir) => dir.remove(SERVICE_MARKER),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Vec<u32> {
        // SAFETY: getuid cannot fail.
        vec![unsafe { libc::getuid() }]
    }

    fn move_mine(from: &Path, to: &Path) -> Result<Moved> {
        move_state(from, to, &me(), &me())
    }

    fn repeater(dir: &Path, key: &[u8]) {
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::write(dir.join(IDENTITY_FILE), key).unwrap();
        std::fs::write(dir.join("roster.bin"), b"roster").unwrap();
        std::fs::write(dir.join("namespaces.json"), b"{}").unwrap();
        std::fs::write(dir.join("docs/inner"), b"nested").unwrap();
        std::fs::write(dir.join("host.lock"), b"").unwrap();
    }

    #[test]
    fn moves_everything_and_leaves_the_source_without_an_identity() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        repeater(&from, &[7; 32]);
        assert_eq!(move_mine(&from, &to).unwrap(), Moved::Moved);
        assert_eq!(std::fs::read(to.join(IDENTITY_FILE)).unwrap(), [7; 32]);
        assert_eq!(std::fs::read(to.join("roster.bin")).unwrap(), b"roster");
        assert_eq!(std::fs::read(to.join("docs/inner")).unwrap(), b"nested");
        assert!(!to.join("host.lock").exists());
        assert!(!has_identity(&from));
        assert!(!from.join("roster.bin").exists());
        assert!(from.join("host.lock").exists());
        assert!(!staging_for(&to).exists());
        // Running it again is a no-op.
        assert_eq!(move_mine(&from, &to).unwrap(), Moved::Nothing);
    }

    #[test]
    fn never_merges_two_identities() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        repeater(&from, &[1; 32]);
        repeater(&to, &[2; 32]);
        assert!(move_mine(&from, &to).is_err());
        assert_eq!(std::fs::read(from.join(IDENTITY_FILE)).unwrap(), [1; 32]);
        assert_eq!(std::fs::read(to.join(IDENTITY_FILE)).unwrap(), [2; 32]);
    }

    #[test]
    fn never_lands_on_a_keyless_roster() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        repeater(&from, &[1; 32]);
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(to.join("roster.bin"), b"someone else's").unwrap();
        assert!(move_mine(&from, &to).is_err());
        assert!(has_identity(&from));
    }

    #[test]
    fn finishes_a_move_interrupted_before_the_source_was_deleted() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        repeater(&from, &[3; 32]);
        repeater(&to, &[3; 32]);
        assert_eq!(move_mine(&from, &to).unwrap(), Moved::Moved);
        assert!(!has_identity(&from));
        assert!(has_identity(&to));
    }

    #[test]
    fn finishes_a_move_interrupted_during_the_swap() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        repeater(&from, &[4; 32]);
        let staging = staging_for(&to);
        repeater(&staging, &[4; 32]);
        std::fs::create_dir_all(&to).unwrap();
        assert_eq!(move_mine(&from, &to).unwrap(), Moved::Moved);
        assert_eq!(std::fs::read(to.join(IDENTITY_FILE)).unwrap(), [4; 32]);
        assert!(!staging.exists());
        assert!(!has_identity(&from));
    }

    #[test]
    fn an_incomplete_staging_copy_is_started_over() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        repeater(&from, &[5; 32]);
        let staging = staging_for(&to);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("roster.bin"), b"partial").unwrap();
        assert_eq!(move_mine(&from, &to).unwrap(), Moved::Moved);
        assert_eq!(std::fs::read(to.join("roster.bin")).unwrap(), b"roster");
    }

    /// A file outside every repeater directory that a planted link points at.
    fn bait(root: &Path) -> PathBuf {
        let secret = root.join("not-yours");
        std::fs::write(&secret, b"root's secret").unwrap();
        secret
    }

    fn untouched(from: &Path, to: &Path, secret: &Path) {
        assert_eq!(std::fs::read(secret).unwrap(), b"root's secret");
        assert!(!to.join(IDENTITY_FILE).exists());
        assert!(!to.join("roster.bin").exists());
        assert!(std::fs::symlink_metadata(from).is_ok());
    }

    #[test]
    fn refuses_a_symlinked_identity() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        let secret = bait(root.path());
        repeater(&from, &[6; 32]);
        std::fs::remove_file(from.join(IDENTITY_FILE)).unwrap();
        std::os::unix::fs::symlink(&secret, from.join(IDENTITY_FILE)).unwrap();
        // Not even an identity, as far as the move is concerned.
        assert!(!has_identity(&from));
        assert_eq!(move_mine(&from, &to).unwrap(), Moved::Nothing);
        untouched(&from, &to, &secret);
    }

    #[test]
    fn refuses_a_symlinked_state_file() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        let secret = bait(root.path());
        repeater(&from, &[6; 32]);
        std::fs::remove_file(from.join("roster.bin")).unwrap();
        std::os::unix::fs::symlink(&secret, from.join("roster.bin")).unwrap();
        let error = move_mine(&from, &to).unwrap_err().to_string();
        assert!(error.contains("symbolic link"), "{error}");
        untouched(&from, &to, &secret);
        assert!(has_identity(&from));
    }

    #[test]
    fn refuses_a_symlink_nested_in_a_state_directory() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        let secret = bait(root.path());
        repeater(&from, &[6; 32]);
        std::os::unix::fs::symlink(&secret, from.join("docs/linked")).unwrap();
        assert!(move_mine(&from, &to).is_err());
        untouched(&from, &to, &secret);
        assert!(has_identity(&from));
    }

    #[test]
    fn refuses_a_symlinked_source_directory_or_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        repeater(&real.join("repeater"), &[8; 32]);
        let secret = bait(root.path());
        let to = root.path().join("service");

        // The state directory itself is a link.
        let linked = root.path().join("linked");
        std::os::unix::fs::symlink(real.join("repeater"), &linked).unwrap();
        assert!(move_mine(&linked, &to).is_err());
        // A directory above it is.
        let above = root.path().join("above");
        std::os::unix::fs::symlink(&real, &above).unwrap();
        assert!(move_mine(&above.join("repeater"), &to).is_err());

        untouched(&real.join("repeater"), &to, &secret);
        assert!(has_identity(&real.join("repeater")));
    }

    #[test]
    fn refuses_a_symlinked_destination_or_staging_directory() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("user");
        repeater(&from, &[9; 32]);
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();

        let to = root.path().join("service");
        std::os::unix::fs::symlink(&elsewhere, &to).unwrap();
        assert!(move_mine(&from, &to).is_err());

        let to = root.path().join("service2");
        std::os::unix::fs::symlink(&elsewhere, staging_for(&to)).unwrap();
        assert!(move_mine(&from, &to).is_err());

        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        assert!(has_identity(&from));
    }

    #[test]
    fn refuses_files_of_another_account() {
        if me() == [0] {
            return; // root owns everything it makes; the check is only visible unprivileged
        }
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        repeater(&from, &[10; 32]);
        let error = move_state(&from, &to, &[u32::MAX - 1], &me())
            .unwrap_err()
            .to_string();
        assert!(error.contains("belongs to uid"), "{error}");
        assert!(has_identity(&from));
    }

    #[test]
    fn the_marker_never_writes_through_a_planted_link() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("user");
        std::fs::create_dir_all(&from).unwrap();
        let secret = bait(root.path());
        std::os::unix::fs::symlink(&secret, from.join(format!("{SERVICE_MARKER}.tmp"))).unwrap();
        mark_moved(&from, &me(), "moved\n").unwrap();
        assert_eq!(std::fs::read(&secret).unwrap(), b"root's secret");
        let marker = std::fs::symlink_metadata(from.join(SERVICE_MARKER)).unwrap();
        assert!(marker.is_file());
        assert_eq!(marker.mode() & 0o777, 0o644);

        // And a marker that is itself a link is removed, never followed.
        std::fs::remove_file(from.join(SERVICE_MARKER)).unwrap();
        std::os::unix::fs::symlink(&secret, from.join(SERVICE_MARKER)).unwrap();
        clear_marker(&from, &me()).unwrap();
        assert!(std::fs::symlink_metadata(from.join(SERVICE_MARKER)).is_err());
        assert!(secret.exists());
    }

    #[test]
    fn chown_tree_refuses_a_symlinked_directory() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let linked = root.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        // SAFETY: getgid cannot fail.
        let (uid, gid) = (me()[0], unsafe { libc::getgid() });
        assert!(chown_tree(&linked, &me(), uid, gid).is_err());
        chown_tree(&real, &me(), uid, gid).unwrap();
    }

    #[test]
    fn copies_keep_a_private_mode() {
        let root = tempfile::tempdir().unwrap();
        let (from, to) = (root.path().join("user"), root.path().join("service"));
        repeater(&from, &[11; 32]);
        move_mine(&from, &to).unwrap();
        for path in [to.clone(), to.join("docs")] {
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        }
        for path in [to.join(IDENTITY_FILE), to.join("docs/inner")] {
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        }
    }
}
