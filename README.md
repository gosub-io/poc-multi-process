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
cargo run --release -- --bench-tiles 500 shm     # measure tile transport…
cargo run --release -- --bench-tiles 500 socket  # …against the copy path
cargo run --release -- --bench-stream 12 ring    # measure body streaming…
cargo run --release -- --bench-stream 12 socket  # …against the copy path
```

### Sandbox: allowlist by default (fail-closed)

Each child installs a seccomp-BPF filter after connecting its IPC link. It is
a default-deny **allowlist**: the component's legitimate syscalls are
enumerated and everything else is a fatal `SIGSYS` (`KillProcess`, not `EPERM`
— a killed process can't probe the sandbox and adapt). This is fail-closed — a
syscall we never considered (a new one, or a bypass such as io_uring-based
networking) is denied for free — which is what real renderer sandboxes
(Chromium, Firefox) do. `src/sandbox/linux.rs` holds the curated baseline.

A few allowed syscalls are **argument-filtered**: `mmap`/`mprotect` are
permitted only when `PROT_EXEC` is clear, so a renderer can never turn writable
memory executable (**W^X**) — the step most memory-corruption exploits need to
run injected code. Startup is fail-closed too: if the filter can't be
installed, the component aborts rather than run unconfined, so multi-process
mode requires seccomp support (use `--single-process` where it's unavailable).

The renderer gets the baseline only: no `socket`/`connect` (no network), no
`openat` (no file opens — so the filesystem is capped without Landlock), no
`execve`/`clone` (no subprocesses), no `io_uring_*`. The net component gets the
same baseline plus the socket family, since it owns network access.

The engine (parent) is unsandboxed, because the privileges a filter would drop
are exactly the ones it exists to exercise: it spawns processes, opens sockets,
and holds the cookie jar. It is *not* unsandboxed because it is safe from
hostile input — it plainly is not. Every frame a renderer or the net component
sends is `bincode::deserialize`d inside the engine (`rx.recv::<FromRenderer>()`
in the loop's reader threads), so a compromised child's bytes are parsed by the
one process holding every secret, with full ambient authority and no filter
behind it.

What bounds that today: frames are length-prefixed and capped at 16 MiB with
the length checked *before* allocating, the wire types are closed enums, and
bincode has no type-directed dispatch — it cannot be steered into constructing
arbitrary types the way a gadget-bearing format (pickle, Java serialization,
`serde_yaml` tags) can. So this is a narrow surface, not an open one. It is
still the sharpest edge in the model, because the whole architecture rests on
the broker being uncompromisable and this is the one place untrusted bytes
reach it.

A production engine would confine the broker too — Chromium sandboxes its
browser process, just far more loosely than a renderer — and would keep the
parser minimal and fuzzed. Neither is done here.

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
├── storage service          filesystem: per-(zone,origin) key/value store
├── font service             filesystem: opens font files, returns metrics
├── audio service            device stub: confined with an ioctl filter
├── gpu service              device stub: confined with an ioctl filter
└── fork server (Linux)      minimal, single-threaded, secret-free
    ├── renderer (zone, A)   Phase 2: per-(zone,origin), unprivileged
    ├── renderer (zone, B)   Phase 2: per-(zone,origin), unprivileged
    └── decoder              ephemeral: forked per image, decodes one, exits
```

Two families of child, split by one rule: **the zygote can only parent a
process strictly less privileged than itself.** Its filter, empty netns and
non-dumpable flag are inherited and only narrow, so anything needing a
capability the zygote gave up cannot be its child.

- *Under the fork server* (content processes, less privileged): renderers, and
  the ephemeral decoder. They fork cheaply from the warm zygote.
- *Off the engine* (services, each needing a capability renderers lack): the
  net component (network), storage and font (`openat`), audio and gpu (device
  `ioctl`). Each is spawned fork+exec with its own filter — a *superset* of the
  content baseline — and, except the net component, an empty netns.

- **Image decoding runs in a throwaway process.** Decoding is the most
  dangerous input a browser handles (libwebp CVE-2023-4863 was a zero-click RCE
  in every major browser), so renderers never parse image bytes themselves —
  they broker a `NeedDecode` to a decoder forked from the zygote, which decodes
  exactly one image and exits. It is a content process with the renderer's
  confinement (no network, files, or exec), so a parser bug is contained; a
  crash is relayed to the renderer as a decode *failure*, never a crash of
  anything else. It is deliberately **ephemeral, not shared**: holding no state,
  a decoder can never see a second origin's image — a single long-lived decoder
  would reintroduce the cross-origin channel the per-`(zone,origin)` split
  closes. The per-image fork is what the warm fork server makes cheap.

- **Filesystem-capable services are separate processes with a wider filter.**
  Renderers deny `openat` outright — the property that caps their filesystem
  without Landlock — which is only sustainable while nothing renders real text
  or persists data. So storage (the `localStorage`/`IndexedDB` stand-in) and
  the font service run outside the zygote with a `baseline + openat` filter.
  Storage is keyed by the `(zone, origin)` the *engine* stamps, never a claim
  in the message, so a renderer cannot read another origin's data; and the
  renderer's key is hashed into the filename rather than spliced into a path,
  since `openat`'s path argument is one seccomp cannot restrict (Landlock is
  the syscall-level answer, still the next step). **Audio and GPU are honest
  stubs**: real processes with the correct device filter (`baseline + openat +
  ioctl`) and empty netns, but no real work — a PoC has no hardware to drive,
  and `ioctl` is a large surface seccomp constrains poorly, so the isolation
  they show is the process boundary, not a tight filter.

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
  CGNAT, `0.0.0.0/8`, multicast, class E, the special-purpose registry blocks
  — TEST-NETs, benchmarking, `192.0.0/24`, 6to4 relay — and the IPv6
  equivalents incl. unique-local and link-local), so it isn't fooled by
  alternate IP encodings (`http://2130706433/`, `0x7f.1`, octal), IPv4-mapped
  IPv6, NAT64/IPv4-compatible embeddings (`64:ff9b::7f00:1`, `::127.0.0.1`),
  userinfo confusion (`http://real.com@127.0.0.1/`), or a trailing dot.
  Subnet-directed broadcast (`x.y.z.255`) is knowingly not classified — it
  depends on the local netmask, and refusing every `.255` would break
  legitimate public hosts.
  It can't resolve *hostnames* offline; a real one resolves DNS, re-checks the
  resolved IPs, and pins that IP for the connection to defeat DNS rebinding.
- Renderers are **sandboxed at the OS level** (Linux): after connecting their
  IPC link, they install a default-deny seccomp-BPF **allowlist** permitting
  only a curated baseline (I/O on existing fds, memory, futex, signals, time).
  A renderer — even one fully code-exec'd by an exploit — physically cannot
  open a socket, an io_uring instance, a file, or a subprocess; the kernel
  returns `EPERM`. See `src/sandbox/linux.rs`. The net component gets the same
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

### Tiles over shared memory (Linux)

In multi-process mode a rendered tile is not copied through the socket: the
renderer rasterizes into a **sealed `memfd`** and passes the *fd* over the
existing `SCM_RIGHTS` channel; the engine maps the same physical pages
read-only and hands the zero-copy view to the compositor
(`TilePixels::Shared`). Only a ~10-byte `TileShm { width, height }` message
travels in-band. This is the channel OOPIFs and a future decode process would
reuse. `src/shm.rs` holds both sides; the lifecycle discipline:

- **Producer seals before sending.** The renderer writes the tile, unmaps, and
  seals `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL` — the
  kernel refuses `F_SEAL_WRITE` while any writable mapping exists, so a sealed
  fd *proves* no writer remains anywhere. There is no window where both
  processes can write the same pages, and the seals can never be lifted.
- **Consumer validates the fd, not the message.** The dimensions in the
  message are a claim: the engine bounds them (≤ 2048², i.e. 16 MiB — the
  same per-message ceiling the in-band frame cap imposes, so shared memory
  never lets a renderer pin *more* engine memory per message than the socket
  path could), requires the seals to actually be present (`F_GET_SEALS`), and
  `fstat`s the fd's *real* size before mapping. `F_SEAL_SHRINK` makes that
  check TOCTOU-free — a malicious renderer can't shrink the fd after
  validation to `SIGBUS` the engine. A tile that fails validation is a
  protocol violation: the engine drops the link (→ `TabCrashed`).
- **No fd leaks — including smuggled ones.** The memfd is `MFD_CLOEXEC`,
  received fds are `MSG_CMSG_CLOEXEC` and wrapped in `OwnedFd`, the
  producer's copy closes right after sending, and the consumer's closes as
  soon as the mapping exists (dropping the `Tile` unmaps). The receive side
  (`ipc::recv_fd`) walks *all* control messages, adopts every fd the kernel
  installed, and enforces exactly-one — a peer stuffing extra fds into the
  hand-off (`sendmsg` is on its allowlist) gets a refusal and every fd
  closed, instead of silently leaking descriptors into the engine's fd table
  until it's exhausted. One sealed memfd per tile; a real compositor at
  60 fps would switch to a reusable buffer pool, which must trade
  `F_SEAL_WRITE` for fence-based ownership handoff (see `src/shm.rs` docs).
- The renderer's sandbox allowlist grows only `memfd_create`, `ftruncate`, and
  `fcntl` argument-filtered to the seal commands — `memfd_create` opens
  nothing on the filesystem, and every mutating `fcntl` (e.g. `F_DUPFD`,
  `F_SETFD` clearing `CLOEXEC`) is still a fatal `SIGSYS`, which the selftest
  probes verify from outside.

Measured, not assumed (`--bench-tiles <frames> <shm|socket>`, release build,
500 × 512²×4 tiles over one tab, every tile byte-compared against the expected
pattern): **2.22 ms/frame via shared memory vs 4.90 ms/frame copied through
the socket** (2.2×), with engine peak RSS 3.6 MB vs 4.6 MB — the ~1 MiB tile
no longer materializes in the engine at all. Single-process mode (and any
shm failure) falls back to the in-band copy; the consumer-side validation
doesn't care which path was taken.

### Large fetch bodies over a shared-memory ring (Linux)

Where a tile is complete-and-immutable (seal everything), a download is a
*stream* — so large fetch bodies use the other end of the shared-memory dial:
a fixed **ring buffer** (`src/ring.rs`, 256 KiB window) that the net component
keeps writing while the renderer keeps reading, wrapping at the end — pipe
semantics without the kernel copy, which is what Chromium's data pipes are.
The engine brokers but never touches the bytes: it routes the in-band header
(`FetchBodyStream { status, body_len }`) and **forwards the ring fd** to the
requesting renderer, so body bytes flow net → renderer directly. What the
ring buys:

- **Constant memory for unbounded data.** The transport holds one window, not
  one body: a 128 MiB body streams through the 256 KiB ring (wrapping ~512
  times) with every process's RSS flat. The 16 MiB IPC frame cap stays
  untouched — it still bounds *messages*; bodies no longer ride in messages.
- **Structural backpressure.** A full ring blocks the producer, an empty one
  blocks the consumer; nobody buffers on the other's behalf (a real net
  component's stalled writes would close the TCP window back to the origin).
  Both sides bound their patience (5 s of zero progress = abandon the
  stream), so a dead or deliberately-stalling peer costs seconds, not a hung
  process — and only that stream, never the component.
- **The trust contract shifts from seals to discipline** — deliberately, per
  transport role. The kernel still guarantees *size* (`F_SEAL_SHRINK|GROW` are
  applied at creation; unlike `F_SEAL_WRITE` they coexist with writers, so the
  consumer's `fstat` check stays TOCTOU-free and no read can `SIGBUS`).
  Contents and cursors are hostile: each side copies the shared read/write
  cursors to locals and validates them against capacity before touching a
  byte (a corrupt cursor is a detected protocol violation, not an OOB read),
  offsets are reduced mod capacity only after that check, and the consumer
  reads **single-pass** — every byte copied out exactly once, never re-read —
  which is the discipline that replaces immutability. Wakeups are shared
  futexes on the cursor words; a producer that dies mid-stream is caught by
  an abort flag, a truncated stream (fewer bytes than promised) is an error.
- **Same lifecycle hygiene as tiles**: `MFD_CLOEXEC`/`MSG_CMSG_CLOEXEC`,
  `OwnedFd` everywhere, producer drops its fd right after sending, consumer
  maps then closes, `F_SEAL_SEAL` stops the peer from adding seals. No new
  syscalls in the sandbox — memfd/seals/futex were already in the baseline,
  and the `ring` selftest probe proves the full dance under renderer lockdown.

The demo exercises it (the personal-zone tab fetches `/blob/4`, a synthesized
4 MiB patterned body; the renderer byte-verifies and reports the transport),
and it is measured (`--bench-stream <MiB> <ring|socket>`, release build):
**12 MiB in 20 ms (596 MiB/s) via the ring vs 134 ms (90 MiB/s) copied
through the socket** — 6.6× — with engine peak RSS **2.7 MB vs 27 MB**, since
the socket path materializes the body in the engine twice (net reply + tab
forward) while the ring path never lets it exist there at all. A 128 MiB body
(impossible in-band) streams at 608 MiB/s with the engine flat at 2.6 MB.
Small responses stay in-band on purpose — a ring costs setup; a few-KB page
does not earn it — as does everything in single-process mode (same address
space, nothing to share).

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
  rejected, tiles arrive via shared memory (multi-process) or in-band copy
  (single-process) and byte-match the expected pattern either way, the tile
  bench completes on both transports, large fetch bodies stream through the
  ring (multi-process) or fall back in-band (single-process) and byte-match
  the producer's pattern either way, the stream bench completes on both
  transports, and (Linux) the children both *announce* and *enforce* their
  seccomp sandbox — the `selftest` probes confirm that making memory
  executable (`PROT_EXEC`), opening a socket, and any `fcntl` beyond the seal
  commands are each killed by `SIGSYS`, while the sealed-memfd tile dance and
  the ring produce/consume dance both survive. The `shm` and `ring` unit
  tests additionally pin the consumer-side refusals: unsealed fds, undersized
  fds, absurd dimensions/lengths, corrupt ring cursors, aborted and truncated
  streams — plus a two-thread ring round-trip that wraps the window 256×.

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
| `src/ipc.rs` | `Endpoint` tx/rx halves (channel/local transports), wire messages, bincode framing, `SCM_RIGHTS` fd-passing (Linux) |
| `src/channel/` | Transport seam: the duplex byte channel a link runs over — `unix.rs` (socketpair), `windows.rs` (anonymous pipe pair) |
| `src/net_daemon.rs` | Net component: `serve` loop, (synthesized) fetching |
| `src/ip_utils.rs` | SSRF policy: URL host extraction, IP-literal parsing (incl. `inet_aton` encodings), blocked-range classification |
| `src/renderer.rs` | Per-`(zone,origin)` renderer: `serve` loop, placeholder render pipeline |
| `src/decoder.rs` | Ephemeral image decoder: bounds-checked `GIMG` parser, decodes one image and exits |
| `src/storage.rs` | Storage service: per-`(zone,origin)` key/value store, keys hashed into filenames |
| `src/font.rs` | Font service: opens a font file, returns only metrics |
| `src/device_service.rs` | Audio + GPU stubs: confined with a device filter, no real work |
| `src/fork_server.rs` | Fork server (Linux): `fork()`s renderers without exec |
| `src/shm.rs` | Shared-memory tiles (Linux): sealed-`memfd` producer + validating consumer |
| `src/ring.rs` | Shared-memory ring (Linux): streams large fetch bodies, futex wakeups, hostile-cursor validation |
| `src/sandbox/` | Privilege capping seam: `linux.rs` (seccomp-BPF, netns, rlimits), `macos.rs` (Seatbelt), `unsupported.rs` (no-ops) |
| `src/selftest.rs` | Sandbox-enforcement probes spawned by the integration tests (Linux) |
| `src/main.rs` | Child-role dispatch for re-exec + minimal event-driven usage |
| `tests/integration.rs` | End-to-end tests running the built binary (both modes + sandbox) |

## Shortcuts taken (what a real implementation needs instead)

The security *mechanisms* are real (see the isolation section); what's
simplified is the surrounding browser. What each entry below still needs:

- **Sandboxing**: the seccomp filter is production-shaped (fail-closed
  allowlist, `KillProcess`, W^X via `PROT_EXEC` argument-filtering), and
  renderers additionally run in an empty **network namespace** — unshared on
  the fork server at spawn and inherited by every renderer it `fork()`s, so
  "a renderer cannot reach the network" no longer rests on the syscall
  allowlist alone. The two layers fail independently: an allowlist gap is
  survivable when the namespace has no interfaces to connect through. The net
  component is the one role that keeps the host netns. Separately, every process
  (engine included, in both modes) clears its **dumpable** flag, so other
  software running as the same user cannot `ptrace`-attach or read
  `/proc/<pid>/mem` — the engine's cookie jar is the obvious target, and this is
  the inbound direction that seccomp has no say over. It is set after `execve`,
  which resets the flag; it survives `fork`, so renderers inherit it from the
  fork server. Still missing for a real
  deployment: a per-arch baseline tested across libc/kernel versions,
  filesystem restriction (Landlock), and the remaining namespaces
  (mount/PID/IPC) plus `pivot_root`. A real JS JIT needs executable memory, so
  it would carve out a dedicated JIT exception rather than deny `PROT_EXEC`
  outright.

  **Platform status.** Linux is the reference implementation: seccomp, an empty
  netns, rlimits, non-dumpable processes, 12 probes. macOS runs a Seatbelt
  profile with 11 probes. Windows spawns over a pair of anonymous pipes (see
  `src/channel/`) and installs **process mitigation policies** — no dynamic
  code (the W^X analogue), no child processes, no injection extension points,
  plus win32k lockdown — with 4 probes.

  Windows is deliberately **half a sandbox**, and worth reading as such. Its
  mitigation policies are self-applied, so they fit the existing contract; the
  access-confining half — a restricted token, an integrity level, an
  AppContainer, a job object — is attached by the *parent* at `CreateProcess`
  and is not implemented. So a Windows renderer cannot run injected code or
  spawn programs, but it can still read files and reach the network, and the
  renderer/net distinction the other backends enforce does not exist there.
  Closing that needs the sixth, parent-side operation described in
  `src/sandbox/mod.rs`.

  Note the netns is obtained via `CLONE_NEWUSER | CLONE_NEWNET` (an unprivileged
  `CLONE_NEWNET` alone needs `CAP_SYS_ADMIN`) and the uid map is deliberately
  left unwritten, so children run as the overflow uid. This makes multi-process
  mode require unprivileged user namespaces, the same way it already requires
  seccomp — hosts without them use `--single-process`.
- **Fetching**: synthesized responses instead of real HTTP; the net component
  handles one request at a time (the engine doesn't block on it, but a real
  daemon would fetch concurrently — with the ring transport that matters
  more, since one slow-draining body stream now occupies the component until
  it completes or hits the 5 s stall timeout). The SSRF filter classifies IP literals but
  can't resolve hostnames offline — production resolves DNS, re-checks the
  result, and pins the IP against rebinding.
- **Event loop & writes**: std threads + mpsc instead of tokio; the real
  engine's worker loops are `select!`-based async tasks. The loop's replies to
  components are *blocking* socket writes, so a renderer that floods requests
  **and** refuses to read its replies can stall the loop (memory stays bounded —
  the per-source gates handle that — but responsiveness doesn't). Non-blocking
  per-channel writes on an async loop fix both. Relatedly, the per-source
  gate bounds what sits *in the engine loop's inbox*, but `FrameReady` events
  ride an unbounded channel to the embedding application — a tile's gate
  permit is returned when the loop forwards it, not when the app drops it, so
  an app that stops draining events accumulates tiles (capped at 16 MiB
  each). A real engine bounds its compositor queue and recycles tile buffers.
- **Tile transport**: implemented over sealed shared memory (see above). What
  a real compositor still needs: a reusable buffer *pool* instead of one memfd
  per tile (fd churn at 60 fps), which trades `F_SEAL_WRITE` for fence-based
  ownership handoff, plus damage rects and a swapchain-style
  acquire/present protocol.
- **Origins**: the engine's `origin_of` now canonicalizes the full
  `scheme://host[:port]` tuple (default ports folded), so different schemes
  or ports are different origins — the cookie jar is partitioned by scheme
  too, closing the HTTPS→HTTP secure-cookie downgrade, and an `https:`
  renderer can't be navigated to `http:`. Still not a real URL parser (no
  IDNA, no userinfo; the SSRF filter's `host_of` remains the
  deliberately-hostile one — a real engine would share one implementation),
  and cross-origin navigation is refused instead of swapping renderers.
- **Fork server**: it is `exec`'d fresh (one exec) rather than forked from the
  engine early to inherit the *engine's* warm libraries; the modeled behavior
  is renderers fork-without-exec from a warm process. It is unsandboxed
  (minimal, trusted, holds no secrets) and reaps its renderers on shutdown; a
  real one would also seccomp-confine itself around the `fork()`/fd-passing
  path. Linux only — `fork()`-without-exec + the Rust runtime relies on
  `fork()` semantics. Elsewhere renderers fall back to direct fork+exec.
- **Phase 3 (GPU process)** is not modeled — structurally it's the same pattern
  as the net component.
