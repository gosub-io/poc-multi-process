# Process Isolation PoC — gosub-engine issue #1080

Proof of concept for
[gosub-io/gosub-engine#1080](https://github.com/gosub-io/gosub-engine/issues/1080)
*"Process Isolation for Security: Multi-Process Architecture"*: an
**event-driven engine** (commands in, events out — shaped like the real gosub
engine) whose components run either as **isolated child processes** (the
issue's architecture) or as **threads in a single process** (classic engine),
over the same component code, IPC protocol, and policy checks.


```sh
cargo run --release                      # multi-process (default)
cargo run --release -- --single-process  # same engine, components as threads
cargo build --no-default-features        # single-process-only binary
cargo test                               # unit + integration suite (see Tests)
```

### Sandbox: allowlist by default (fail-closed)

Each child installs a seccomp-BPF filter after connecting its IPC link. It is
a default-deny **allowlist**: the component's legitimate syscalls are
enumerated and everything else is a fatal `SIGSYS` (`KillProcess`, not `EPERM`
— a killed process can't probe the sandbox and adapt). This is fail-closed — a
syscall we never considered (a new one, or a bypass such as io_uring-based
networking) is denied for free — which is what real renderer sandboxes
(Chromium, Firefox) do. `src/sandbox.rs` holds the curated baseline.

A few allowed syscalls are **argument-filtered**: `mmap`/`mprotect` are
permitted only when `PROT_EXEC` is clear, so a renderer can never turn writable
memory executable (**W^X**) — the step most memory-corruption exploits need to
run injected code. Startup is fail-closed too: if the filter can't be
installed, the component aborts rather than run unconfined, so multi-process
mode requires seccomp support (use `--single-process` where it's unavailable).

The renderer gets the baseline only: no `socket`/`connect` (no network), no
`openat` (no file opens — so the filesystem is capped without Landlock), no
`execve`/`clone` (no subprocesses), no `io_uring_*`. The net component gets the
same baseline plus the socket family, since it owns network access. The engine
(parent) is unsandboxed on purpose — it is the trusted core that spawns
processes and holds secrets, and it never parses untrusted bytes.

## Event-driven engine

Mirroring gosub-engine's `EngineCommand`/`TabCommand`/`EngineEvent` shape
(`src/events.rs`): you send commands through an `EngineHandle` and react to
events from a channel — nothing blocks, and frames from different tabs arrive
in whatever order the renderers finish.

```rust
let (engine, events) = engine::start(mode);
engine.open_tab("https://example.com")?;

for event in events {
    match event {
        EngineEvent::TabOpened { tab_id, origin } => engine.navigate(tab_id, url)?,
        EngineEvent::FrameReady { tab_id, tile } => { /* composite */ }
        EngineEvent::TabCrashed { tab_id }       => { /* only that tab died */ }
        ...
    }
}
```

Commands: `OpenTab`, `Tab { Navigate | Close }`, `SetCookie`, `Shutdown`.
Events: `TabOpened`, `FrameReady`, `NavigationFailed`, `TabCrashed`,
`TabClosed`, `EngineShutdown`, …

Internally (`src/engine.rs`) the engine is one event-loop thread with a
single inbox — the std-only equivalent of the real engine's `tokio::select!`
worker loop. Cheap reader threads forward every message source into it:

```text
EngineHandle ── EngineCommand ──▶ ┌────────────┐ ──▶ EngineEvent
                                  │ event loop │
renderer/net reader threads ────▶ └────────────┘ ──▶ replies to components
```

Because the loop never blocks on any one component, fetches for many tabs are
multiplexed over the single net link with **request ids** (`pending_fetches`
maps each reply back to the tab that asked).

## Isolation architecture

```
engine event loop (broker — owns cookie jar & policy)
├── net component            Phase 1: sole owner of network capability
└── fork server (Linux)      minimal, single-threaded, secret-free
    ├── renderer (zone, A)   Phase 2: per-(zone,origin), unprivileged
    └── renderer (zone, B)   Phase 2: per-(zone,origin), unprivileged
```

- Renderers hold no secrets: cookies and network access live in the engine
  and net component. A renderer can only send IPC messages, and every message
  is policy-checked in the event loop (`tab_request`).
- Identity is **`(zone, origin)`**, ambient and not claimed. A *zone* is a
  storage/cookie partition (browser profile / container tabs — "Work",
  "Personal"), matching gosub's own `Zone` concept; the engine keys its cookie
  jar by `(ZoneId, origin)`, and a renderer process is bound to one
  `(zone, origin)`. So the same origin opened in two zones runs as two separate
  processes with independent cookie jars — one can never touch the other's
  partition. The engine knows each tab's `(zone, origin)` because *it* spawned
  the renderer; identity fields inside messages are never trusted. Navigation
  is same-origin per renderer (site isolation).
- **HttpOnly cookies never reach a renderer.** Cookies carry an `http_only`
  flag; the net component receives all of a request's cookies to attach to the
  outbound fetch (it must — that's how authenticated requests work), but a
  renderer asking for `document.cookie` gets only the non-HttpOnly ones. So an
  exploited `example.com` renderer never sees `example.com`'s session token —
  it travels engine → net and skips the renderer's address space entirely.
- SSRF policy is centralized in the net component (the one place allowed to
  open sockets), so no renderer bug can bypass it. It classifies the *numeric*
  address (loopback, private incl. `172.16/12`, link-local/cloud-metadata,
  CGNAT, `0.0.0.0/8`, and the IPv6 equivalents), so it isn't fooled by
  alternate IP encodings (`http://2130706433/`, `0x7f.1`, octal), IPv4-mapped
  IPv6, userinfo confusion (`http://real.com@127.0.0.1/`), or a trailing dot.
  It can't resolve *hostnames* offline; a real one resolves DNS, re-checks the
  resolved IPs, and pins that IP for the connection to defeat DNS rebinding.
- Renderers are **sandboxed at the OS level** (Linux): after connecting their
  IPC link, they install a default-deny seccomp-BPF **allowlist** permitting
  only a curated baseline (I/O on existing fds, memory, futex, signals, time).
  A renderer — even one fully code-exec'd by an exploit — physically cannot
  open a socket, an io_uring instance, a file, or a subprocess; the kernel
  returns `EPERM`. See `src/sandbox.rs`. The net component gets the same
  baseline plus the socket family.
- Children run under **OS resource caps** the engine sets at spawn (Linux):
  `RLIMIT_AS` (512 MiB address space), `RLIMIT_NOFILE`, and `RLIMIT_CORE=0`.
  seccomp caps *what* a child may do; these cap *how much*, so a compromised
  renderer can't exhaust host memory/fds — an over-allocation aborts that
  process, not the machine — and a crash won't dump a core full of secrets.
- On the IPC side, the shared event-loop inbox is **bounded per source**. Every
  component (each renderer, the net process) may have at most
  `MAX_QUEUED_PER_SOURCE` messages queued-but-unprocessed: its reader thread
  takes a permit before forwarding a message and the loop returns one after
  handling it. When a source runs out of permits its reader stops draining that
  socket, so the OS backpressures the component itself. Because the bound is
  *per source*, one compromised renderer flooding any message type pins a fixed
  slice of engine memory and can't crowd out other tabs — without it, a flood
  grows the engine ~90 MB/s to OOM; with it, engine RSS stays flat. In-flight
  fetches are *additionally* bounded per tab (`MAX_INFLIGHT_FETCHES`).
- A crashed renderer surfaces as `EngineEvent::TabCrashed` for that tab only;
  the engine and all other tabs keep running (in multi-process mode).
- Children are reached via an **inherited `socketpair(2)` fd**, not a socket on
  disk. Possessing the fd is the authentication — it cannot be forged — so
  there is no rendezvous path, no auth token on argv (which any local user
  could read from `/proc/<pid>/cmdline`), and no `accept()` race. Every other
  fd the engine holds stays `CLOEXEC`, so one renderer never inherits another's
  channel.
- Renderers are created by a **fork server** (Linux), the way Firefox (a
  "fork server") and Chromium/Android (a "zygote") do it — see below.

### Fork server (Linux)

Renderers are not `exec`'d from scratch; they are **`fork()`ed without `exec`**
from a dedicated *fork server* process, so each new renderer inherits an
already-initialized runtime copy-on-write instead of re-running full process
startup. Two reasons drive it, one speed and one safety:

- **Speed** — `fork()` without `exec()` skips re-linking and re-initializing the
  runtime for every content process (the dominant win in a real browser).
- **Safety** — you fork from a *minimal, single-threaded, secret-free* snapshot.
  The engine can't be that snapshot: it is multithreaded (forking it would
  strand locks other threads hold) and it owns the cookie jar (a fork would
  inherit it). So the fork server exists solely to be a clean thing to fork
  from. It is brought up before the engine loads any cookies.

The engine still creates each renderer's `socketpair`, keeps one end, and passes
the other to the fork server via **`SCM_RIGHTS`** fd-passing — so the renderer
talks straight to the engine even though the fork server is its OS parent. The
forked child then drops privileges (its own seccomp filter; rlimits inherited
from the fork server) and serves. Crash detection is unchanged: the engine holds
the renderer's socket end, so a dead renderer still surfaces as `TabCrashed`
regardless of which process is its OS parent; the fork server reaps the corpse.

You can see it in a syscall trace: only `fork-server` and `net-daemon` are ever
`execve`'d — the renderers appear only as `clone()`/`fork()` from the fork
server, with no exec. The net component (a one-off) is still spawned directly.

## Single- vs multi-process: two-level selection

The same trick as Chromium's `--single-process`: components are written once,
only transport and spawning differ.

- **Compile time** — the `multi-process` cargo feature (default on) gates all
  process-spawning and Unix-socket code. `--no-default-features` produces a
  single-process-only engine, e.g. for platforms without fork/UDS (WASM would
  be the real motivation in gosub).
- **Run time** — when the feature is compiled in, `--single-process` selects
  the thread-based setup; `--multi-process`/no flag selects isolation.

The seam is `ipc::Endpoint`: send/receive halves (`EndpointTx`/`EndpointRx`,
splittable so the event loop can hand the receive half to a reader thread)
over either `UnixStream` or in-process channels, both carrying identical
length-framed bincode messages (with a max-frame check so a corrupt length
prefix can't force an unbounded allocation). Components expose a
transport-agnostic `serve(Endpoint, ...)` loop; the feature-gated `run()`
wrappers are only the child-process entry points. The engine's `Spawner`
either spawns a thread wired with `local_pair()`, or (multi-process) hands the
child one end of a `socketpair(2)` — the net component by fork+exec, renderers
by asking the fork server to `fork()` them. It is the only code that knows
which mode is active.

Note: in single-process mode the policy checks still run, but a compromised
renderer *thread* shares the engine's address space — the checks only become
a real security boundary with a process behind them.

## Tests

`cargo test` runs two layers:

- **Unit tests** (in `src/`) cover the pure policy/logic deterministically: the
  SSRF classifier (internal ranges, alternate IP encodings, IPv6,
  userinfo/trailing-dot bypasses), the cookie broker (`(zone, origin)`
  partitioning + HttpOnly hiding), IPC frame round-trip and oversized-length
  rejection, the per-source backpressure `Gate`, and origin parsing. The
  single-process engine is also driven end to end (open → navigate → frame →
  close → shutdown, cross-origin refusal, unparseable URL) — the broker/policy
  code is identical in both modes, so this exercises the real thing.
- **Integration tests** (`tests/integration.rs`) run the actual built binary:
  multi- and single-process runs render and shut down cleanly, unknown args are
  rejected, and (Linux) the children both *announce* and *enforce* their seccomp
  sandbox — the `selftest` probes confirm that making memory executable
  (`PROT_EXEC`) and opening a socket are each killed by `SIGSYS`.

Two properties are checked by hand rather than in `cargo test`, as they need
external tooling: the fork server forking renderers *without* exec (an `execve`
strace shows only `fork-server`/`net-daemon`, never `renderer`) and the
per-source inbox bound holding engine RSS flat under a message flood (RSS
sampling: ~2.8 MB steady vs. ~90 MB/s growth without it). The `Gate` unit test
covers the bounding mechanism itself deterministically.

## Layout

| File | Contents |
|------|----------|
| `src/events.rs` | Public vocabulary: `EngineCommand`, `TabCommand`, `EngineEvent`, `TabId`, `Tile` |
| `src/engine.rs` | `start(mode)`, `EngineHandle`, the event loop (broker + policy), `Spawner` |
| `src/ipc.rs` | `Endpoint` tx/rx halves (socket/local transports), wire messages, bincode framing |
| `src/net_daemon.rs` | Net component: `serve` loop, SSRF policy, (synthesized) fetching |
| `src/renderer.rs` | Per-`(zone,origin)` renderer: `serve` loop, placeholder render pipeline |
| `src/fork_server.rs` | Fork server (Linux): `fork()`s renderers without exec; `SCM_RIGHTS` fd-passing |
| `src/sandbox.rs` | seccomp-BPF privilege capping for the child processes (Linux) |
| `src/selftest.rs` | Sandbox-enforcement probes spawned by the integration tests (Linux) |
| `src/main.rs` | Child-role dispatch for re-exec + minimal event-driven usage |
| `tests/integration.rs` | End-to-end tests running the built binary (both modes + sandbox) |

## Shortcuts taken (what a real implementation needs instead)

The security *mechanisms* are real (see the isolation section); what's
simplified is the surrounding browser. What each entry below still needs:

- **Sandboxing**: the seccomp filter is production-shaped (fail-closed
  allowlist, `KillProcess`, W^X via `PROT_EXEC` argument-filtering). Still
  missing for a real deployment: a per-arch baseline tested across libc/kernel
  versions, filesystem restriction (Landlock), and namespaces/`pivot_root` for
  defense in depth. A real JS JIT needs executable memory, so it would carve out
  a dedicated JIT exception rather than deny `PROT_EXEC` outright.
  macOS/Windows need their own mechanisms (Seatbelt, AppContainer).
- **Fetching**: synthesized responses instead of real HTTP; the net component
  handles one request at a time (the engine doesn't block on it, but a real
  daemon would fetch concurrently). The SSRF filter classifies IP literals but
  can't resolve hostnames offline — production resolves DNS, re-checks the
  result, and pins the IP against rebinding.
- **Event loop & writes**: std threads + mpsc instead of tokio; the real
  engine's worker loops are `select!`-based async tasks. The loop's replies to
  components are *blocking* socket writes, so a renderer that floods requests
  **and** refuses to read its replies can stall the loop (memory stays bounded —
  the per-source gates handle that — but responsiveness doesn't). Non-blocking
  per-channel writes on an async loop fix both.
- **Tile transport**: tiles are copied through the socket. At real frame rates
  you'd use shared memory (`memfd` + fd-passing) and send only the handle — the
  `SCM_RIGHTS` fd-passing primitive this needs already exists
  (`fork_server::send_fd`).
- **Origins**: the engine's `origin_of` is a `scheme://host` string prefix, not
  a real URL parser/origin tuple, and cross-origin navigation is refused instead
  of swapping renderers. (Note the inconsistency: the SSRF filter's `host_of`
  *is* a careful parser — a real engine would share one origin implementation.)
- **Fork server**: it is `exec`'d fresh (one exec) rather than forked from the
  engine early to inherit the *engine's* warm libraries; the modeled behavior
  is renderers fork-without-exec from a warm process. It is unsandboxed
  (minimal, trusted, holds no secrets) and reaps its renderers on shutdown; a
  real one would also seccomp-confine itself around the `fork()`/fd-passing
  path. Linux only — `fork()`-without-exec + the Rust runtime relies on
  `fork()` semantics. Elsewhere renderers fall back to direct fork+exec.
- **Phase 3 (GPU process)** is not modeled — structurally it's the same pattern
  as the net component.
