//! `update`: replace the installed daemon's binary with the newest Linux release, and restart it.
//!
//! The Windows repeater updates itself through Velopack and the macOS app through Sparkle; this is
//! the Linux twin, small enough to need neither. `install` puts a systemd timer next to the daemon
//! (`streetcryptid-repeater-update.timer`, every six hours, on unless `--auto-update off`) that runs
//! this command from the installed copy.
//!
//! **Where releases are found.** Linux releases are GitHub prereleases among several tag families,
//! so "the latest release" says nothing about them. The release workflow therefore keeps one fixed
//! prerelease, `linux-updates`, whose `latest.json` names the newest version, its tag, and each
//! architecture's tarball with its SHA-256 (the `macos-updates` appcast is the same idea). It is
//! only ever moved forward.
//!
//! **What is trusted.** The feed and the archive come over HTTPS from GitHub (redirects only to
//! HTTPS, at most five), and the archive must hash to the feed's SHA-256 — the same trust a person
//! extends by downloading a release, and the Windows updater's. There is no separate signature yet.
//! Everything else is checked before anything is replaced: the feed's tag and file name must be
//! exactly the ones the workflow publishes for that version and this architecture, only the one
//! binary is taken from the archive, the unpacked binary must report the version the feed promised
//! (which also proves it runs on this glibc), and an update never moves backwards.
//!
//! **How it is swapped.** Under a lock, the installed binary is kept as `.previous`, the new one is
//! renamed over it (atomic), and a daemon that was running is restarted — `Type=notify`, so
//! `systemctl restart` returns only once the new one is up. If it does not come up, the previous
//! binary is put back and started again. A daemon that was stopped stays stopped. The unit files
//! are not touched: re-running `install` refreshes those.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::install::{self, BINARY, SYSTEM_LIB_DIR};
use crate::paths::SERVICE_NAME;
use crate::VERSION;

/// Where releases are published (the `origin` every release workflow runs in).
pub const REPOSITORY: &str = "https://github.com/crypt-o-graphic/streetCryptid";
/// The fixed prerelease whose `latest.json` names the newest Linux release.
pub const FEED_TAG: &str = "linux-updates";
pub const FEED_ASSET: &str = "latest.json";

const MAX_FEED_BYTES: usize = 64 * 1024;
const MAX_ARCHIVE_BYTES: usize = 128 << 20;
const MAX_BINARY_BYTES: u64 = 256 << 20;
const MAX_REDIRECTS: usize = 5;

const STAGED: &str = ".streetcryptid-repeater.new";
const PREVIOUS: &str = ".streetcryptid-repeater.previous";
const LOCK: &str = ".update.lock";

/// `latest.json`, as the release workflow writes it.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub tag: String,
    pub assets: BTreeMap<String, Asset>,
}

#[derive(Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub sha256: String,
}

/// One architecture's build of the newest release, checked against what the workflow publishes.
#[derive(Debug, PartialEq, Eq)]
pub struct Release {
    pub version: Version,
    pub url: String,
    pub sha256: String,
    /// The binary's path inside the tarball.
    pub member: String,
}

impl Manifest {
    pub fn release_for(&self, arch: &str, repository: &str) -> Result<Release> {
        let version = Version::parse(&self.version)
            .map_err(|_| anyhow!("the update feed names an unreadable version"))?;
        // The canonical spelling only: it goes into a URL and a path below.
        if version.to_string() != self.version || !version.build.is_empty() {
            bail!("the update feed names an unreadable version");
        }
        if self.tag != format!("linux-v{version}") {
            bail!("the update feed's tag does not match its version {version}");
        }
        let asset = self
            .assets
            .get(arch)
            .ok_or_else(|| anyhow!("release {version} has no build for {arch}"))?;
        let stem = format!("streetcryptid-repeater-{version}-{arch}-linux");
        if asset.name != format!("{stem}.tar.gz") {
            bail!("the update feed names an unexpected file for {arch}");
        }
        let sha256 = asset.sha256.to_ascii_lowercase();
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("the update feed's checksum for {arch} is malformed");
        }
        Ok(Release {
            url: format!("{repository}/releases/download/{}/{}", self.tag, asset.name),
            sha256,
            member: format!("{stem}/{BINARY}"),
            version,
        })
    }
}

/// Only a strictly newer release is installed. An installed binary whose version cannot be read is
/// broken or not ours to judge, and the newest release replaces it.
pub fn is_newer(installed: Option<&Version>, latest: &Version) -> bool {
    installed.is_none_or(|installed| latest > installed)
}

/// `streetcryptid-repeater 1.2.3` (clap's `--version`) → 1.2.3.
fn parse_version_output(output: &str) -> Option<Version> {
    let version = output.trim().strip_prefix(&format!("{BINARY} "))?;
    Version::parse(version).ok()
}

/// What `exe --version` reports, or `None` if it does not run or answers something else.
pub fn reported_version(exe: &Path) -> Option<Version> {
    // A binary just written can be briefly busy (ETXTBSY) while another thread's fork still holds
    // the write descriptor; that clears within moments.
    for _ in 0..20 {
        match Command::new(exe).arg("--version").output() {
            Ok(output) if output.status.success() => {
                return parse_version_output(&String::from_utf8_lossy(&output.stdout));
            }
            Ok(_) => return None,
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The one binary in a release tarball: a regular file at exactly `member`, nothing else.
pub fn extract_binary(archive: &[u8], member: &str) -> Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries().context("reading the release archive")? {
        let mut entry = entry.context("reading the release archive")?;
        if entry.path().ok().as_deref() != Some(Path::new(member)) {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            bail!("the release archive's {BINARY} is not a regular file");
        }
        let mut binary = Vec::new();
        (&mut entry)
            .take(MAX_BINARY_BYTES + 1)
            .read_to_end(&mut binary)
            .context("unpacking the release archive")?;
        if binary.len() as u64 > MAX_BINARY_BYTES {
            bail!("the release archive's {BINARY} is implausibly large");
        }
        return Ok(binary);
    }
    bail!("the release archive has no {member}")
}

/// Write `binary` beside the installed one (same filesystem, so the swap is a rename), 0755.
fn stage(dir: &Path, binary: &[u8]) -> Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let staged = dir.join(STAGED);
    let _ = std::fs::remove_file(&staged);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&staged)
        .with_context(|| format!("writing {}", staged.display()))?;
    file.write_all(binary)?;
    file.sync_all()?;
    Ok(staged)
}

/// Put `staged` in place of `binary`, restarting the daemon if it was `running`; if the new one does
/// not start, put the previous one back and start that.
pub fn swap(
    binary: &Path,
    staged: &Path,
    running: bool,
    mut restart: impl FnMut() -> Result<()>,
) -> Result<()> {
    let previous = binary.with_file_name(PREVIOUS);
    let _ = std::fs::remove_file(&previous);
    std::fs::hard_link(binary, &previous)
        .with_context(|| format!("keeping a copy of {}", binary.display()))?;
    std::fs::rename(staged, binary).with_context(|| format!("replacing {}", binary.display()))?;
    if running {
        if let Err(error) = restart() {
            std::fs::rename(&previous, binary)
                .with_context(|| format!("putting the previous {} back", binary.display()))?;
            return match restart() {
                Ok(()) => Err(anyhow!(
                    "the new version did not start ({error}); the previous one is back and running"
                )),
                Err(_) => Err(anyhow!(
                    "the new version did not start ({error}); the previous one is back in place \
                     but did not start either"
                )),
            };
        }
    }
    let _ = std::fs::remove_file(&previous);
    Ok(())
}

/// One update at a time: the timer and a person can both run one.
fn lock(dir: &Path) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(LOCK))
        .with_context(|| format!("locking {}", dir.display()))?;
    // SAFETY: a valid fd; the lock lives as long as the returned file.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("Another update of the repeater is already running.");
    }
    Ok(file)
}

fn describe(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("streetCryptid-repeater-updater/{VERSION}"))
        .https_only(true)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else if attempt.url().scheme() != "https" {
                attempt.error("redirected away from HTTPS")
            } else {
                attempt.follow()
            }
        }))
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| anyhow!("setting up HTTPS: {}", describe(&e)))
}

/// `url`'s body, at most `cap` bytes; `None` when it is not there (404).
async fn get(client: &reqwest::Client, url: &str, cap: usize) -> Result<Option<Vec<u8>>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("fetching {url}: {}", describe(&e)))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("fetching {url}: HTTP {}", response.status());
    }
    if response
        .content_length()
        .is_some_and(|len| len > cap as u64)
    {
        bail!("fetching {url}: larger than expected");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| anyhow!("fetching {url}: {}", describe(&e)))?
    {
        if body.len() + chunk.len() > cap {
            bail!("fetching {url}: larger than expected");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// The newest release for this machine, or `None` if nothing has been published yet.
fn latest(runtime: &tokio::runtime::Runtime, client: &reqwest::Client) -> Result<Option<Release>> {
    let url = format!("{REPOSITORY}/releases/download/{FEED_TAG}/{FEED_ASSET}");
    let Some(body) = runtime.block_on(get(client, &url, MAX_FEED_BYTES))? else {
        return Ok(None);
    };
    let manifest: Manifest =
        serde_json::from_slice(&body).map_err(|_| anyhow!("the update feed is unreadable"))?;
    manifest
        .release_for(std::env::consts::ARCH, REPOSITORY)
        .map(Some)
}

/// The installed daemon this command updates.
struct Installed {
    user: bool,
    dir: PathBuf,
}

impl Installed {
    fn locate(system: bool, check: bool) -> Result<Self> {
        if system {
            if !check && !install::is_root() {
                bail!(
                    "Updating the machine's repeater needs root: `sudo streetcryptid-repeater \
                     update --system`."
                );
            }
            Ok(Self {
                user: false,
                dir: PathBuf::from(SYSTEM_LIB_DIR),
            })
        } else if install::is_root() {
            bail!("As root, update the machine's repeater with `update --system`.")
        } else {
            Ok(Self {
                user: true,
                dir: install::user_lib_dir()?,
            })
        }
    }

    fn binary(&self) -> PathBuf {
        self.dir.join(BINARY)
    }

    fn systemctl(&self, args: &[&str]) -> Command {
        let mut command = Command::new("systemctl");
        if self.user {
            command.arg("--user");
        }
        command.args(args);
        command
    }

    fn daemon_running(&self) -> bool {
        self.systemctl(&["is-active", "--quiet", SERVICE_NAME])
            .status()
            .is_ok_and(|s| s.success())
    }

    fn restart(&self) -> Result<()> {
        let output = self
            .systemctl(&["restart", SERVICE_NAME])
            .output()
            .context("running systemctl")?;
        if !output.status.success() {
            bail!(
                "`systemctl restart {SERVICE_NAME}` failed ({})",
                output.status
            );
        }
        Ok(())
    }

    fn command(&self) -> &'static str {
        if self.user {
            "streetcryptid-repeater update"
        } else {
            "sudo streetcryptid-repeater update --system"
        }
    }
}

pub fn update(system: bool, check: bool) -> Result<()> {
    let installed = Installed::locate(system, check)?;
    let binary = installed.binary();
    let present = binary.exists();
    if !present && !check {
        bail!(
            "There is no installed repeater in {} to update. `install{}` puts one there; a binary \
             you run by hand is updated by downloading the new release.",
            installed.dir.display(),
            if installed.user { "" } else { " --system" }
        );
    }
    // Held through the download, so two updates never fetch or swap at once.
    let _lock = if check {
        None
    } else {
        Some(lock(&installed.dir)?)
    };
    let current = present.then(|| reported_version(&binary)).flatten();
    let runtime = runtime()?;
    let client = client()?;
    let latest = latest(&runtime, &client)?;

    if check {
        println!("This binary:     {VERSION}");
        match (&current, present) {
            (Some(version), _) => println!("Installed:       {version} ({})", binary.display()),
            (None, true) => println!("Installed:       unknown ({})", binary.display()),
            (None, false) => println!("Installed:       none in {}", installed.dir.display()),
        }
        let Some(latest) = latest else {
            println!("Latest release:  none published to the update feed yet");
            return Ok(());
        };
        println!("Latest release:  {}", latest.version);
        if present {
            if is_newer(current.as_ref(), &latest.version) {
                println!("`{}` installs it.", installed.command());
            } else {
                println!("Up to date.");
            }
        }
        return Ok(());
    }

    let Some(latest) = latest else {
        println!("No Linux release has been published to the update feed yet.");
        return Ok(());
    };
    if !is_newer(current.as_ref(), &latest.version) {
        if let Some(current) = &current {
            println!("The repeater is up to date ({current}).");
        }
        return Ok(());
    }

    println!("Downloading the repeater {}…", latest.version);
    let archive = runtime
        .block_on(get(&client, &latest.url, MAX_ARCHIVE_BYTES))?
        .ok_or_else(|| {
            anyhow!(
                "release {} is in the update feed but not published",
                latest.version
            )
        })?;
    if sha256_hex(&archive) != latest.sha256 {
        bail!(
            "the downloaded release does not match the update feed's checksum; nothing was changed"
        );
    }
    let staged = stage(&installed.dir, &extract_binary(&archive, &latest.member)?)?;
    if reported_version(&staged).as_ref() != Some(&latest.version) {
        let _ = std::fs::remove_file(&staged);
        bail!(
            "the downloaded repeater {} does not run on this machine (or reports another version); \
             nothing was changed",
            latest.version
        );
    }
    let running = installed.daemon_running();
    swap(&binary, &staged, running, || installed.restart())?;
    let from = current.map_or_else(|| "an unknown version".to_string(), |v| v.to_string());
    if running {
        println!(
            "Updated the repeater from {from} to {} and restarted it.",
            latest.version
        );
    } else {
        println!(
            "Updated the repeater from {from} to {}; it was not running, so it was left stopped.",
            latest.version
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str, tag: &str, name: &str, sha256: &str) -> Manifest {
        serde_json::from_value(serde_json::json!({
            "version": version,
            "tag": tag,
            "assets": { "x86_64": { "name": name, "sha256": sha256 } },
        }))
        .unwrap()
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ABCDEF";

    #[test]
    fn the_feed_names_exactly_the_published_asset() {
        let release = manifest(
            "1.4.0",
            "linux-v1.4.0",
            "streetcryptid-repeater-1.4.0-x86_64-linux.tar.gz",
            SHA,
        )
        .release_for("x86_64", "https://example.test/r")
        .unwrap();
        assert_eq!(
            release,
            Release {
                version: Version::new(1, 4, 0),
                url: "https://example.test/r/releases/download/linux-v1.4.0/streetcryptid-repeater-1.4.0-x86_64-linux.tar.gz".into(),
                sha256: SHA.to_ascii_lowercase(),
                member: "streetcryptid-repeater-1.4.0-x86_64-linux/streetcryptid-repeater".into(),
            }
        );
    }

    #[test]
    fn a_feed_that_says_anything_else_is_refused() {
        let good = "streetcryptid-repeater-1.4.0-x86_64-linux.tar.gz";
        for (version, tag, name, sha) in [
            ("1.4.0", "linux-v1.3.0", good, SHA),
            ("1.4.0", "v1.4.0", good, SHA),
            ("01.4.0", "linux-v01.4.0", good, SHA),
            ("1.4.0+x", "linux-v1.4.0+x", good, SHA),
            ("1.4.0", "linux-v1.4.0", "../../../etc/passwd", SHA),
            (
                "1.4.0",
                "linux-v1.4.0",
                "streetcryptid-repeater-1.4.0-aarch64-linux.tar.gz",
                SHA,
            ),
            ("1.4.0", "linux-v1.4.0", good, &SHA[1..]),
            ("1.4.0", "linux-v1.4.0", good, &SHA.replace('a', "g")),
        ] {
            assert!(
                manifest(version, tag, name, sha)
                    .release_for("x86_64", REPOSITORY)
                    .is_err(),
                "accepted {version} {tag} {name} {sha}"
            );
        }
        assert!(manifest("1.4.0", "linux-v1.4.0", good, SHA)
            .release_for("aarch64", REPOSITORY)
            .is_err());
    }

    #[test]
    fn only_a_newer_release_is_installed() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(is_newer(Some(&v("1.3.9")), &v("1.4.0")));
        assert!(is_newer(Some(&v("1.4.0-rc.1")), &v("1.4.0")));
        assert!(is_newer(Some(&v("0.0.0-ci.812")), &v("0.1.0")));
        assert!(!is_newer(Some(&v("1.4.0")), &v("1.4.0")));
        assert!(!is_newer(Some(&v("1.5.0")), &v("1.4.0")));
        assert!(is_newer(None, &v("1.4.0")));
    }

    #[test]
    fn the_version_is_read_from_the_binary_itself() {
        assert_eq!(
            parse_version_output("streetcryptid-repeater 1.4.0\n"),
            Some(Version::new(1, 4, 0))
        );
        assert_eq!(parse_version_output("something-else 1.4.0"), None);
        assert_eq!(parse_version_output("streetcryptid-repeater nope"), None);

        let dir = tempfile::tempdir().unwrap();
        let script = stage(
            dir.path(),
            b"#!/bin/sh\necho 'streetcryptid-repeater 2.0.1-rc.3'\n",
        )
        .unwrap();
        assert_eq!(
            reported_version(&script),
            Some(Version::parse("2.0.1-rc.3").unwrap())
        );
        assert_eq!(reported_version(&dir.path().join("missing")), None);
    }

    fn tarball(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, data, kind) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            if kind.is_symlink() {
                header.set_link_name("/bin/sh").unwrap();
            }
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn only_the_binary_is_taken_from_the_archive() {
        let member = "streetcryptid-repeater-1.4.0-x86_64-linux/streetcryptid-repeater";
        let archive = tarball(&[
            (
                "streetcryptid-repeater-1.4.0-x86_64-linux/README.md",
                b"readme",
                tar::EntryType::Regular,
            ),
            (member, b"\x7fELF new", tar::EntryType::Regular),
        ]);
        assert_eq!(extract_binary(&archive, member).unwrap(), b"\x7fELF new");
        assert!(extract_binary(&archive, "elsewhere/streetcryptid-repeater").is_err());

        let linked = tarball(&[(member, b"", tar::EntryType::Symlink)]);
        assert!(extract_binary(&linked, member).is_err());
        assert!(extract_binary(b"not a tarball", member).is_err());
    }

    fn installed(dir: &Path, contents: &[u8]) -> (PathBuf, PathBuf) {
        let binary = dir.join(BINARY);
        std::fs::write(&binary, b"old").unwrap();
        (binary, stage(dir, contents).unwrap())
    }

    #[test]
    fn a_running_daemon_is_restarted_on_the_new_binary() {
        let dir = tempfile::tempdir().unwrap();
        let (binary, staged) = installed(dir.path(), b"new");
        let mut restarts = 0;
        swap(&binary, &staged, true, || {
            restarts += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(restarts, 1);
        assert_eq!(std::fs::read(&binary).unwrap(), b"new");
        assert!(!dir.path().join(PREVIOUS).exists());
        assert!(!staged.exists());
    }

    #[test]
    fn a_new_binary_that_does_not_start_is_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let (binary, staged) = installed(dir.path(), b"new");
        let mut restarts = Vec::new();
        let error = swap(&binary, &staged, true, || {
            restarts.push(std::fs::read(&binary).unwrap());
            if restarts.len() == 1 {
                bail!("start failed")
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(restarts, [b"new".to_vec(), b"old".to_vec()]);
        assert_eq!(std::fs::read(&binary).unwrap(), b"old");
        assert!(error
            .to_string()
            .contains("previous one is back and running"));
    }

    #[test]
    fn a_stopped_daemon_stays_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let (binary, staged) = installed(dir.path(), b"new");
        swap(&binary, &staged, false, || panic!("restarted")).unwrap();
        assert_eq!(std::fs::read(&binary).unwrap(), b"new");
    }

    #[test]
    fn one_update_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let held = lock(dir.path()).unwrap();
        assert!(lock(dir.path()).is_err());
        drop(held);
        assert!(lock(dir.path()).is_ok());
    }
}
