# Process Isolation PoC — gosub-engine issue #1080

Runnable proof of concept for
[gosub-io/gosub-engine#1080](https://github.com/gosub-io/gosub-engine/issues/1080)
*"Process Isolation for Security: Multi-Process Architecture"*.

```sh
cargo run --release                      # multi-process (the issue's architecture)
cargo run --release -- --single-process  # same engine, components as threads
```

No external services needed; the network daemon synthesizes HTTP responses so
the demo is offline and deterministic.

## Single- vs multi-process: two-level selection

The engine supports both setups over the **same component code and broker
protocol** — only the transport and spawning differ (this is how Chromium's
`--single-process` works too):

- **Compile time** — the `multi-process` cargo feature (default on) gates all
  process-spawning and Unix-socket code. `cargo build --no-default-features`
  produces a single-process-only engine, e.g. for platforms without
  fork/UDS (WASM would be the real motivation in gosub).
- **Run time** — when the feature is compiled in, `--single-process` still
  selects the thread-based setup (debugging, constrained targets), and
  `--multi-process`/no flag selects isolation.

The seam is `ipc::Endpoint` (`src/ipc.rs`): an enum over
`Socket(UnixStream)` and `Local(mpsc channels)`. Components (`renderer.rs`,
`net_daemon.rs`) expose a transport-agnostic `serve(Endpoint, ...)` loop; the
feature-gated `run()` wrappers are only the process entry points. The parent's
`Spawner` either spawns a thread with a `local_pair()` or re-execs the binary
and accepts the socket connection. Every policy check (`drive_render`) is
shared, so behavior is identical in both modes — except where a process
boundary is the point:

- **Demo 2** in single-process mode prints a caveat: the policy holds at the
  IPC layer, but a real exploit in a renderer *thread* reads the cookie jar
  straight out of shared memory. The checks only become a boundary with
  processes behind them.
- **Demo 4** (crash containment) is skipped in single-process mode, because
  the simulated exploit's `abort()` would kill the entire browser — exactly
  the failure mode the issue eliminates.

## What it demonstrates

One binary re-execs itself into the process tree from the issue (or spawns
the same components as threads in single-process mode):

```
engine (parent, broker — owns cookie jar & policy)
├── net-daemon               Phase 1: sole owner of network capability
├── renderer example.com     Phase 2: per-origin, unprivileged
└── renderer attacker.com    Phase 2: per-origin, unprivileged
```

All IPC is **length-framed bincode** (`src/ipc.rs`) — over Unix domain
sockets in multi-process mode, over in-process channels in single-process
mode — with a max-frame check so a corrupt/malicious length prefix can't
force an unbounded allocation.

| Demo | Issue claim exercised |
|------|----------------------|
| 1. Normal render | Renderer fetches subresources and reads its *own* cookies only via the broker; ships a rasterized tile back (the ~1 MB texture/frame budget). |
| 2. Compromised renderer | `attacker.com`'s renderer tries to read `example.com` cookies (denied — the broker checks the request against the **socket's identity**, never the message contents) and tries SSRF to `169.254.169.254` (denied by the net daemon's centralized policy). |
| 3. Latency | 100 full frames (brokered fetch + cookie lookup + 1 MiB tile transfer) measured against the issue's **<10 ms/frame** acceptance criterion. On this machine: ~3.4 ms avg multi-process, ~1.5 ms single-process — i.e. the isolation tax is ~2 ms/frame here. |
| 4. Crash containment | The compromised renderer aborts (stand-in for the rasterizer buffer overflow in the issue's threat model). The engine reaps it via SIGABRT and re-renders `example.com` to show the rest of the browser is unaffected. |

## Key design points carried over from the issue

- **Renderers hold no secrets.** Cookies, DOM-of-record, and network access
  live in the parent/net-daemon. A renderer that is fully code-exec'd can only
  send IPC messages, and every message is policy-checked.
- **Identity is ambient, not claimed.** The broker knows which origin each
  socket belongs to because *it* spawned the process; an origin field inside a
  message is never trusted.
- **SSRF policy is centralized** in the one process that can open sockets,
  so no renderer bug can bypass it.

## Shortcuts taken (what a real implementation needs instead)

- **Rendezvous**: children connect to a socket path and authenticate with an
  argv token. Real implementation: inherit one end of `socketpair(2)` — 
  unforgeable, nothing on disk.
- **Sandboxing**: the renderer merely *doesn't* do network/file I/O; nothing
  stops it. Real implementation: seccomp-BPF/Landlock (Linux) so the syscalls
  are actually denied, plus namespaces/pledge equivalents per platform.
- **Fetching**: synthesized responses instead of real HTTP.
- **Concurrency**: the broker drives one renderer at a time, synchronously. A
  real engine needs an async broker loop (or a thread per child) and
  request IDs for multiplexing.
- **Tile transport**: tiles are copied through the socket. At real frame rates
  you'd use shared memory (`memfd` + fd-passing over the socket) and only send
  the handle.
- Phase 3 (GPU process) is not modeled — structurally it's the same pattern as
  the net daemon.
