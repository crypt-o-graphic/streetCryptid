# Linux repeater — agent notes

One Rust binary, `streetcryptid-repeater` (crate `streetcryptid-repeater-linux`): the daemon
(`run`), its CLI (`status`, `claim`, `settings`, `watch`) and the opt-in systemd install. Read
`README.md` first. The root `AGENTS.md` still applies.

## How it fits

- The node, identity, settings, snapshot and line protocol come from the desktop host
  (`../host`, crate `streetcryptid-repeater-host`), which the Windows host binary is built from
  too. A change to what a desktop repeater does is a change there, tested there, and ships on both
  platforms; this crate only adds what is Linux's: the Unix socket, systemd, logind, the move into
  `/var/lib`.
- The management plane is the Windows service's protocol, not a new one: a `service` line and the
  latest snapshot on connect, snapshots and arrivals after, and the host's commands (`settings`,
  `name`, `release`; `streetcryptid_repeater_host::Action`) and nothing else. Keep it that way;
  anything a CLI needs that a snapshot lacks belongs in the snapshot, for both platforms.
- The claim link is `streetcryptid_repeater::wire::claim_url`, through the host's snapshot. Never
  format it again, and never print it anywhere but an interactive terminal: under systemd stdout
  is the journal.
- The identity move (`migrate.rs`) is the Windows `StateMigration` step for step. Its guarantees
  (key last, resumable, never merge two identities) are what the tests pin.
- Everything Linux-only is behind `#[cfg(target_os = "linux")]`, so the workspace still checks on
  Windows and macOS.

- Updates (`update.rs`) come from `releases/download/linux-updates/latest.json`, which the
  release workflow advances only after the `linux-v` release exists, and never backwards. The
  feed's checksum over HTTPS is the whole trust chain (there is no signature yet), so `update.rs`
  accepts only the exact asset name and tag the workflow writes, and a staged binary must report
  the feed's version before it replaces anything. A restart that fails puts the previous binary
  back. `install` writes the timer and its oneshot unit; the system one is sandboxed to write only
  the binary's directory, and `test-service.sh` proves that sandbox still allows an update's work.

## Build and test

Always name the package: `cargo test --profile repeater-test -p streetcryptid-repeater-host -p
streetcryptid-repeater-linux`, `cargo build --profile desktop-release -p
streetcryptid-repeater-linux`. On June's Windows machine build in WSL with the target directory
on the Linux side (`CARGO_TARGET_DIR=$HOME/sc-target`), not on `/mnt/c`.

`scripts/test-daemon.sh` runs the built binary unprivileged. `scripts/test-service.sh` installs the
real system service; CI runs it, and so may a throwaway WSL distribution or VM, never a machine
anyone cares about.

## CI and releases

- CI's Linux lane (`.github/workflows/ci-repeater-linux.yml`) runs when this directory, the
  desktop host, the protocol or the workspace's shared files change (`scripts/ci-changes.sh`).
- A push to main that touches what the binary is built from cuts `linux-vX.Y.Z`
  (`.github/workflows/release-repeater-linux.yml`, `scripts/next-repeater-version.sh linux`).
  Commit types decide it: `feat(linux)`/`fix(linux)` release; so does a `feat`/`fix` in
  `repeater/host` or the server crate.
