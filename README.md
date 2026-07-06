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
```

### Sandbox: allowlist by default (fail-closed)

Each child installs a seccomp-BPF filter after connecting its IPC link. It is
a default-deny **allowlist**: the component's legitimate syscalls are
enumerated and everything else returns `EPERM`. This is fail-closed — a
syscall we never considered (a new one, or a bypass such as io_uring-based
networking) is denied for free — which is what real renderer sandboxes
(Chromium, Firefox) do. `src/sandbox.rs` holds the curated baseline.

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
├── renderer origin A        Phase 2: per-origin, unprivileged
└── renderer origin B        Phase 2: per-origin, unprivileged
```

- Renderers hold no secrets: cookies and network access live in the engine
  and net component. A renderer can only send IPC messages, and every message
  is policy-checked in the event loop (`tab_request`).
- Identity is ambient, not claimed: the engine knows which origin each tab's
  renderer belongs to because *it* spawned the component; origin fields inside
  messages are never trusted. Navigation is same-origin per renderer (site
  isolation) — a real engine would swap renderer processes on cross-origin
  navigation.
- SSRF policy is centralized in the net component (the one place allowed to
  open sockets), so no renderer bug can bypass it.
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
  On the IPC side, in-flight fetches are bounded per tab
  (`MAX_INFLIGHT_FETCHES`) so a renderer can't grow the engine unbounded by
  flooding `NeedFetch`.
- A crashed renderer surfaces as `EngineEvent::TabCrashed` for that tab only;
  the engine and all other tabs keep running (in multi-process mode).
- Children are reached via an **inherited `socketpair(2)` fd**, not a socket on
  disk. Possessing the fd is the authentication — it cannot be forged — so
  there is no rendezvous path, no auth token on argv (which any local user
  could read from `/proc/<pid>/cmdline`), and no `accept()` race. Every other
  fd the engine holds stays `CLOEXEC`, so one renderer never inherits another's
  channel.

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
either spawns a thread wired with `local_pair()` or re-execs the binary and
accepts the socket connection — it is the only code that knows which mode is
active.

Note: in single-process mode the policy checks still run, but a compromised
renderer *thread* shares the engine's address space — the checks only become
a real security boundary with a process behind them.

## Layout

| File | Contents |
|------|----------|
| `src/events.rs` | Public vocabulary: `EngineCommand`, `TabCommand`, `EngineEvent`, `TabId`, `Tile` |
| `src/engine.rs` | `start(mode)`, `EngineHandle`, the event loop (broker + policy), `Spawner` |
| `src/ipc.rs` | `Endpoint` tx/rx halves (socket/local transports), wire messages, bincode framing |
| `src/net_daemon.rs` | Net component: `serve` loop, SSRF policy, (synthesized) fetching |
| `src/renderer.rs` | Per-origin renderer: `serve` loop, placeholder render pipeline |
| `src/sandbox.rs` | seccomp-BPF privilege capping for the child processes (Linux) |
| `src/main.rs` | Child-role dispatch for re-exec + minimal event-driven usage |

## Shortcuts taken (what a real implementation needs instead)

- **Rendezvous**: children inherit one end of a `socketpair(2)` — unforgeable,
  nothing on disk, no token on argv. (Earlier revisions used a socket path +
  argv token; that leaked the token through `/proc/<pid>/cmdline` and is gone.)
- **Sandboxing**: seccomp-BPF with a default-deny allowlist
  (`src/sandbox.rs`). Production would go a bit further still — `KillProcess`
  instead of `EPERM` (a denied syscall should be fatal, not merely fail), a
  per-arch baseline tested across libc/kernel versions, and truly *fail-closed*
  startup (refuse to run if the filter can't be installed, rather than warn and
  continue). Namespaces/`pivot_root` add defense in depth. macOS/Windows need
  their own mechanisms (Seatbelt, AppContainer).
- **Fetching**: synthesized responses instead of real HTTP; the net component
  handles one request at a time (the engine doesn't block on it, but a real
  daemon would fetch concurrently).
- **Event loop**: std threads + mpsc instead of tokio; the real engine's
  worker loops are `select!`-based async tasks.
- **Tile transport**: tiles are copied through the socket. At real frame rates
  you'd use shared memory (`memfd` + fd-passing over the socket) and only send
  the handle.
- **Origins**: `scheme://host` string prefix, not a real URL parser/origin
  tuple; cross-origin navigation is refused instead of swapping renderers.
- Phase 3 (GPU process) is not modeled — structurally it's the same pattern as
  the net component.
