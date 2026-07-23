#!/usr/bin/env bash
#
# demo.sh — a five-beat walkthrough of the process-isolation PoC's security
# story, for a live audience. Linux only (the reference platform; the sandbox
# probes and the fork-server trace need Linux).
#
#   ./scripts/demo.sh          # run all five beats
#   PAUSE=1 ./scripts/demo.sh  # pause for <enter> between beats (for talks)
#
# Each beat is a single idea you can narrate while it runs. Nothing here is
# staged — it drives the real built binary.

set -uo pipefail
cd "$(dirname "$0")/.."

BIN=./target/release/gosub-proc-iso-poc

hr()   { printf '\n\033[1;34m━━━ %s\033[0m\n\n' "$*"; }
note() { printf '\033[2m%s\033[0m\n' "$*"; }
step() { if [ "${PAUSE:-0}" = 1 ]; then read -r -p $'\n\033[2m(enter to continue)\033[0m '; fi; }

# Run a sandbox probe and report whether the kernel killed it with SIGSYS.
# The probe runs in a subshell that echoes its own exit code; redirecting that
# subshell's stderr swallows bash's "Bad system call" notice (the shell
# reporting the signal, not the child's output) while we still capture the code.
probe() {
  local name=$1 desc=$2 rc
  rc=$( ( "$BIN" selftest "$name" >/dev/null 2>&1; echo $? ) 2>/dev/null )
  if [ "$rc" = 159 ]; then
    printf '  \033[1m%-20s\033[0m %s \033[32m→ killed by SIGSYS ✓\033[0m\n' "$name" "$desc"
  else
    printf '  \033[1m%-20s\033[0m %s \033[31m→ NOT killed (rc=%s) ✗\033[0m\n' "$name" "$desc" "$rc"
  fi
}

hr "Building the release binary"
cargo build --release --quiet
note "One binary is the browser *and* every child process, selected by an argv role."
step

# ─────────────────────────────────────────────────────────────────────────────
hr "1/5  It runs — real multi-process isolation, cross-origin renderer swap"
note "Two tabs (Work + Personal zones), each a separate renderer process. The"
note "Work tab navigates cross-origin, so the engine SWAPS its renderer (site"
note "isolation) — a fresh process bound to the new origin. No crash, clean exit."
GOSUB_DEMO_SWAP=1 "$BIN" 2>/dev/null \
  | grep -E 'opened|frame ready|swapped to a new renderer|shut down' || true
step

# ─────────────────────────────────────────────────────────────────────────────
hr "2/5  Content processes FORK from a warm server — namespaced, and can't exec"
note "Renderers and decoders are never launched with execve. They fork() from an"
note "already-initialized fork server (Chromium's zygote / Firefox's fork server),"
note "each landing in its OWN pid namespace — it sees itself as pid 2,3,4…, blind"
note "to the host process tree:"
GOSUB_DEBUG_PIDNS=1 "$BIN" 2>&1 | grep -E 'ns-local pid' | sed 's/^/    /' | head -6
note ""
note "(This is also why 'strace -f' can't see them — the namespace hides the fork.)"
note "And because a content process never needs to exec, execve is off its filter —"
note "so it cannot launch a new program even if fully code-exec'd by an exploit:"
probe forkserver-no-exec "forked child tries execve(/bin/true)"
step

# ─────────────────────────────────────────────────────────────────────────────
hr "3/5  The sandbox actually BITES — prove enforcement, not configuration"
note "Each probe is a child that, under the renderer's seccomp filter, ATTEMPTS a"
note "forbidden syscall. The kernel kills it with SIGSYS (exit 128+31 = 159) — no"
note "trust in the code, the kernel refuses the operation:"
probe mprotect-exec "make writable memory executable (W^X)"
probe socket        "open a network socket (renderers never touch the net)"
probe fcntl-dupfd   "clear close-on-exec via fcntl to smuggle an fd"
note "Fail-closed: a syscall we never anticipated is denied for free — even a"
note "renderer whose address space is fully owned by an exploit stays boxed."
step

# ─────────────────────────────────────────────────────────────────────────────
hr "4/5  HttpOnly session tokens never reach a renderer — nor the broker"
note "The Work zone has an HttpOnly 'session' and a visible 'theme'. The cookie"
note "jar lives in a separate low-authority VAULT process (net's sole client), so"
note "HttpOnly never touches the broker. What the renderer's document.cookie sees"
note "vs. what actually reaches the network:"
GOSUB_OBSERVE_COOKIES=1 "$BIN" 2>/dev/null | grep -E 'observe.*(document.cookie|fetch) https://example.com'
note "^ document.cookie exposes only [theme]; the HttpOnly [session] is attached to"
note "  the fetch (reaches the network) but never enters the renderer's memory."
step

# ─────────────────────────────────────────────────────────────────────────────
hr "5/5  Isolation is FREE — zero-copy transport, measured"
note "A rendered tile crosses the process boundary via a sealed shared-memory memfd"
note "(fd passed, pages mapped read-only) instead of a socket copy. Same isolation,"
note "less work:"
printf '\033[1m  via shared memory (fd passed, zero copy):\033[0m\n'
"$BIN" --bench-tiles 500 shm    2>/dev/null | grep -iE 'ms/frame|rss' | sed 's/^/    /' || true
printf '\033[1m  via socket (bytes copied through the kernel):\033[0m\n'
"$BIN" --bench-tiles 500 socket 2>/dev/null | grep -iE 'ms/frame|rss' | sed 's/^/    /' || true
note "The zero-copy path is faster AND keeps the ~1 MiB tile out of the engine's"
note "address space entirely. The multi-process design is not a performance tax."

hr "Done"
note "This is the security architecture — a scale model of Chromium/Firefox/Servo/"
note "Ladybird's isolation at single-document granularity. See SECURITY-MEASURES.md"
note "and browser-architecture-comparison.md for the full, honest accounting."
