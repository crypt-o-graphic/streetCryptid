#!/usr/bin/env bash
# android-heap.sh — a native heap profile of the app on a phone over adb (heapprofd via Perfetto),
# symbolized against the Rust library's symbol copy and summarized by crate and call site.
#
#   start [hours] [dump_minutes]   attach heapprofd to the running app; default 6 h, a dump every 10 min
#   status                         is a session running, and how big is its trace
#   stop                           end the session early (the trace is finalized, not lost)
#   pull                           copy the trace off the phone into $SC_PROFILE_OUT
#   report [--run ID | --commit SHA | --symbols DIR] [trace]
#                                  symbolize (symbols from a CI run's `android-native-symbols`
#                                  artifact, or a local directory) and print where the heap grew
#
# Why this and not telemetry: `process.memory` says HOW MUCH Rust holds (`memory.rust_live_bytes`)
# and `net.conns` says how many connections and tasks there are, but not WHAT holds it. On
# 2026-11-21 a Pixel 10 held 1.7 GB of Rust heap after 75 h and nothing could name the owner.
# heapprofd samples every allocation the process makes after it attaches (Poisson, by bytes) with
# its full native stack, and keeps it until it is freed; a leak is what is still unfreed at the end.
#
# What it needs:
#   - the app running on the phone (open it once; the foreground service keeps it alive), and an
#     internal build: `withProfileable` marks every developer-telemetry build profileable, which
#     is what lets the adb shell attach to a release build.
#   - for `report`: python3, `llvm-symbolizer` (the NDK's, or on PATH), the `perfetto` Python
#     package (installed into a private venv on first use), and `gh` if you pass --run/--commit.
#     The app's library must be a build with a build id (eas-build-pre-install.sh, 2026-11-21 on).
#
# Leave it running for hours: the leak measured on 2026-11-21 was ~20 MB/h, so a short session
# finds churn, not the leak. The sampling costs the app some CPU while attached and nothing after.
set -euo pipefail
# Git Bash on Windows rewrites arguments that look like POSIX paths, device paths included.
export MSYS_NO_PATHCONV=1

APP="${SC_APP_ID:-com.unrealjune.streetcryptid}"
DEVICE_TRACE="/data/misc/perfetto-traces/sc-heap.perfetto-trace"
DEVICE_CONFIG="/data/misc/perfetto-configs/sc-heap.pbtxt"
# A detached session, controlled by its key: once perfetto has daemonized, the shell user may not
# signal it (SELinux), so a `--background` session could not be stopped early.
SESSION="sc_heap"
OUT="${SC_PROFILE_OUT:-.profiles/android-heap}"
CACHE="${SC_PROFILE_CACHE:-$HOME/.cache/streetcryptid/perfetto}"
here="$(cd "$(dirname "$0")" && pwd)"

die() {
  echo "android-heap: $*" >&2
  exit 1
}

adb_sh() { adb shell "$@" | tr -d '\r'; }

app_pid() { adb_sh pidof "$APP" || true; }

session_running() {
  adb shell "perfetto --is_detached=$SESSION > /dev/null 2>&1; echo \$?" 2> /dev/null |
    tr -d '\r' | tail -n1 | grep -qx 0
}

cmd_start() {
  local hours="${1:-6}" dump_min="${2:-10}"
  [[ "$hours" =~ ^[1-9][0-9]*$ && "$dump_min" =~ ^[1-9][0-9]*$ ]] ||
    die "hours and minutes are whole numbers above zero"
  local pid
  pid="$(app_pid)"
  [[ -n "$pid" ]] || die "$APP is not running on the phone; open it once and run this again"
  if session_running; then
    die "a session is already running (\`$0 status\`, \`$0 stop\`)"
  fi
  # 32 KiB mean sampling interval: fine enough to see a 20 MB/h leak by call site within an hour,
  # coarse enough that a phone on the move stays usable. Continuous dumps make the growth readable
  # over time; write_into_file streams the buffer to disk so a six-hour session never fills it.
  # heapprofd takes one session per process and refuses a second (`heapprofd_rejected_concurrent`).
  local config
  config="$(cat << EOF
buffers { size_kb: 65536 fill_policy: RING_BUFFER }
data_sources {
  config {
    name: "android.heapprofd"
    target_buffer: 0
    heapprofd_config {
      sampling_interval_bytes: 32768
      process_cmdline: "$APP"
      shmem_size_bytes: 8388608
      block_client: true
      continuous_dump_config { dump_phase_ms: 60000 dump_interval_ms: $((dump_min * 60000)) }
    }
  }
}
duration_ms: $((hours * 3600000))
write_into_file: true
file_write_period_ms: 60000
flush_period_ms: 60000
EOF
)"
  printf '%s\n' "$config" | adb shell "cat > $DEVICE_CONFIG"
  adb shell "perfetto --detach=$SESSION --txt -c $DEVICE_CONFIG -o $DEVICE_TRACE" > /dev/null 2>&1 ||
    die "perfetto refused the session"
  session_running || die "the session did not start"
  echo "heapprofd attached to $APP (pid $pid) for ${hours} h, a dump every ${dump_min} min."
  echo "Check with \`$0 status\`; end early with \`$0 stop\`; then \`$0 pull\`."
}

cmd_status() {
  local state=1
  if session_running; then
    echo "running; app pid $(app_pid)"
    state=0
  else
    echo "not running"
  fi
  adb_sh "ls -l $DEVICE_TRACE 2>/dev/null" || true
  return "$state"
}

cmd_stop() {
  session_running || die "no session is running"
  # Ends the session and finalizes the file; nothing already recorded is lost.
  adb shell "perfetto --attach=$SESSION --stop" > /dev/null 2>&1 || die "perfetto would not stop"
  echo "stopped; \`$0 pull\` copies the trace off the phone"
}

cmd_pull() {
  local dest
  dest="$OUT/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$dest"
  adb pull "$DEVICE_TRACE" "$dest/heap.perfetto-trace" > /dev/null
  echo "$dest/heap.perfetto-trace"
}

find_symbolizer() {
  if command -v llvm-symbolizer > /dev/null 2>&1; then
    command -v llvm-symbolizer
    return
  fi
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${LOCALAPPDATA:-/nonexistent}/Android/Sdk}}"
  local candidate
  for candidate in "${ANDROID_NDK_HOME:-/nonexistent}"/toolchains/llvm/prebuilt/*/bin/llvm-symbolizer* \
    "$sdk"/ndk/*/toolchains/llvm/prebuilt/*/bin/llvm-symbolizer*; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  return 1
}

python_env() {
  local venv="$CACHE/venv"
  local py="$venv/bin/python"
  [[ -x "$py" ]] || py="$venv/Scripts/python.exe"
  if [[ ! -x "$py" ]]; then
    mkdir -p "$CACHE"
    python3 -m venv "$venv" >&2
    py="$venv/bin/python"
    [[ -x "$py" ]] || py="$venv/Scripts/python.exe"
    "$py" -m pip install --quiet perfetto >&2
  fi
  printf '%s\n' "$py"
}

symbols_for() { # symbols_for <--run ID | --commit SHA | --symbols DIR>
  case "$1" in
    --symbols)
      printf '%s\n' "$2"
      ;;
    --run | --commit)
      local run="$2"
      if [[ "$1" == --commit ]]; then
        run="$(gh run list --commit "$2" --json databaseId,name \
          --jq '[.[] | select(.name | test("PR standalone|Release"))][0].databaseId')"
        [[ -n "$run" && "$run" != null ]] || die "no build run found for commit $2"
      fi
      local dir="$CACHE/symbols/$run"
      if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        local target="$dir"
        command -v cygpath > /dev/null 2>&1 && target="$(cygpath -m "$dir")"
        gh run download "$run" --name android-native-symbols --dir "$target" ||
          die "run $run has no android-native-symbols artifact (built before 2026-11-21?)"
      fi
      printf '%s\n' "$dir"
      ;;
    *) die "report needs --run ID, --commit SHA or --symbols DIR" ;;
  esac
}

cmd_report() {
  local mode="${1:-}" value="${2:-}" trace="${3:-}"
  [[ -n "$mode" && -n "$value" ]] || die "report needs --run ID, --commit SHA or --symbols DIR"
  if [[ -z "$trace" ]]; then
    trace="$(ls -t "$OUT"/*/heap.perfetto-trace 2> /dev/null | head -n1 || true)"
    [[ -n "$trace" ]] || die "no trace under $OUT; run \`$0 pull\` first"
  fi
  local symbols symbolizer py script
  symbols="$(symbols_for "$mode" "$value")"
  symbolizer="$(find_symbolizer)" ||
    die "llvm-symbolizer not found: install the NDK or put llvm-symbolizer on PATH"
  py="$(python_env)"
  # Git Bash on Windows: the venv's python.exe cannot open /c/... paths.
  if command -v cygpath > /dev/null 2>&1; then
    trace="$(cygpath -m "$trace")"
    symbols="$(cygpath -m "$symbols")"
    symbolizer="$(cygpath -m "$symbolizer")"
    script="$(cygpath -m "$here/heap_report.py")"
  else
    script="$here/heap_report.py"
  fi
  echo "trace:   $trace" >&2
  echo "symbols: $symbols" >&2
  "$py" "$script" --trace "$trace" --symbols "$symbols" --symbolizer "$symbolizer"
}

case "${1:-}" in
  start) shift; cmd_start "$@" ;;
  status) cmd_status ;;
  stop) cmd_stop ;;
  pull) cmd_pull ;;
  report) shift; cmd_report "$@" ;;
  *)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
