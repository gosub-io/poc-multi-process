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
enumerated and everything else is a fatal `SIGSYS` — the process is killed, not
handed an `EPERM` it could probe and adapt to. The violation traps through a
`SECCOMP_RET_TRAP` handler that first names the offending call on stderr
(`[sandbox] SIGSYS: blocked syscall #N — terminating`) and then re-raises
SIGSYS, so termination is exactly as before — the process still dies with the
same signal the selftest probes assert — but you now learn *which* syscall it
was. That diagnostic earns its keep once V8 lands and the renderer starts
issuing calls we did not anticipate ("renderer died" becomes "renderer tried
`openat` (#257), killed"). The handler's only added privilege is `tgkill`,
argument-filtered to SIGSYS-to-self so it cannot poke any other process or
signal. This is fail-closed — a syscall we never considered (a new one, or a
bypass such as io_uring-based networking) is denied for free — which is what
real renderer sandboxes (Chromium, Firefox) do. `src/sandbox/linux.rs` holds
the curated baseline.

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

The engine (parent) can't be capped to a renderer's *allowlist*: the privileges
that would drop are exactly the ones it exists to exercise — it spawns
processes, opens sockets, and holds the cookie jar. What it *does* carry is a
**deny-list** seccomp filter (see the broker paragraph below): the broad surface
stays, but the escalation syscalls it never needs are a fatal `SIGSYS`. It is
*not* exempt because it is safe from hostile input — it plainly is not. Every
frame a renderer or the net component sends is `bincode::deserialize`d inside the
engine (`rx.recv::<FromRenderer>()` in the loop's reader threads), so a
compromised child's bytes are parsed by the one process holding every secret,
with full ambient authority over that memory — the deny-list removes
kernel-escalation reach, not the parser's reach into those secrets.

What bounds that today: frames are length-prefixed and capped at 16 MiB with
the length checked *before* allocating, the wire types are closed enums, and
bincode has no type-directed dispatch — it cannot be steered into constructing
arbitrary types the way a gadget-bearing format (pickle, Java serialization,
`serde_yaml` tags) can. Those parsers are also fuzzed (see Fuzzing). So this is
a narrow surface, not an open one. It is still the sharpest edge in the model,
because the whole architecture rests on the broker being uncompromisable and
this is the one place untrusted bytes reach it.

The broker is not left *entirely* unconfined, though. Like Chromium's browser
process — which is sandboxed, just far more loosely than a renderer — it gets
two loose, best-effort layers. A **Landlock sandbox** on the filesystem: it may
read and execute anywhere (it must, to spawn children and load their libraries),
but may only *write* beneath the temp dir — so a broker subverted through the
deserialization surface cannot plant persistence, overwrite its own binary, or
corrupt the user's files. And a **deny-list seccomp filter**: it keeps the broad
syscall surface it genuinely needs (exec, threads, files, sockets — which is why
a renderer-style allowlist does not fit, and why Chromium's browser process is
not allowlisted either), but the escalation primitives it never uses are a fatal
`SIGSYS` — `ptrace`/`process_vm_*`, kernel-module loading, `kexec`, `bpf`,
`perf_event_open`, `userfaultfd`, the keyring, `mount`/`setns`/`pivot_root`. So a
broker compromise can no longer reach for a kernel exploit. Every denied syscall
is also one no child needs, because this filter is inherited before each child
installs its own stricter allowlist. See `lock_down_broker` in `src/sandbox/`.

## What a real renderer would force open

W^X is not a one-off exception — it is the clearest case of a broader pattern:
several of the tightest measures here are enforceable *only because this renderer
is a stub*. A production renderer (a real JIT plus a full media/GPU/worker stack)
would force each of them open, and then compensate elsewhere — which is exactly
what Chromium and Firefox do. Naming them keeps the honest ones honest and stops
"we enforce X" from reading as "a real browser could too":

- **W^X (`PROT_EXEC` denial)** — a JIT needs writable→executable memory, and
  `dlopen`ing a media codec or GPU driver maps code executable *after* the sandbox
  is on. The fix is a narrow JIT/loader carve-out (one RWX region, or a
  dual-mapping `memfd` RX+RW alias), not blanket RX. (Chromium even disables Intel
  CET in the renderer for the JIT.)
- **No threads** — the renderer baseline has no `clone` at all, and the fork
  server filters `clone` to a plain fork (no `CLONE_THREAD`/`CLONE_VM`). A real
  renderer is deeply multithreaded: V8's compiler and GC threads, the
  compositor/raster threads, Web Workers, WASM. `clone` with the thread flags has
  to be allowed — arguably the biggest relaxation after W^X, and easy to miss
  because this renderer happens to be single-threaded.
- **The renderer memory cap** (*axis already fixed*) — this was `RLIMIT_AS =
  512 MiB`, a *virtual* address-space cap enforceable only because the renderer is
  JIT-less: V8's pointer-compression cage reserves ~4 GiB up front, so that cap
  would kill it at init. The PoC now bounds the *heap* instead — `RLIMIT_DATA`,
  which since Linux 4.7 ignores `PROT_NONE` reservations — with a generous 16 GiB
  `RLIMIT_AS` kept only as a virtual sanity ceiling. On top of that, the engine
  now places each spawned child in its own **cgroup v2 `memory.max`** (best-effort
  — the real *physical* bound, whose OOM kill is scoped to the offending child
  rather than the global killer reaching the broker); the rlimit is the
  self-applied approximation that still applies where cgroup delegation is absent.
  Chromium likewise does not `RLIMIT_AS` its renderers. (Per-*renderer* cgroups
  are a further step — see the cgroup note in `src/sandbox/linux.rs`.)
- **Zero file opens** — a real renderer still needs runtime `openat` for
  ICU/locale data, fonts, the GPU shader cache, `dlopen`'d libraries, and
  `/proc/self/maps`; "no `openat` ever" is tighter than reality. It moves to a
  path broker + Landlock rather than an outright denial.
- **Net component is outbound-only** — no `bind`/`listen`, which is right for a
  fetcher, but WebRTC's ICE/STUN/TURN binds local UDP sockets. Real-time media
  reopens `bind` (QUIC is fine — it is connected UDP).
- **Crash reporting vs. the inbound-debug lockdown** (*resolved by self-capture*)
  — `PR_SET_DUMPABLE=0` plus the broker's `ptrace`/`process_vm_readv` denial and
  `RLIMIT_CORE=0` mean no *other* process can read a crashed one to build a report.
  Rather than threading that needle with a privileged handler, the PoC does what
  Crashpad does on Linux: the crashing process **self-captures** a scrubbed report
  (signal + faulting address, no memory contents) from its own signal handler
  before dying — no `ptrace`, no dumpable relaxation, no core. See "Crash
  reporting" below.

For calibration, what *survives* contact with a real browser and stays as-is: no
raw sockets in the renderer and its empty network namespace, no `execve`
anywhere, the brokered network and HttpOnly stripping, default-deny seccomp as a
*posture* (the allowlist just grows with V8), and the `clone3`→`ENOSYS` zygote
model. So W^X belongs to a class of **stub-only guarantees** — each relaxed, then
compensated for — not a lone asterisk.

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

- **Filesystem-capable services are separate processes with a wider filter,
  path-confined by Landlock.** Renderers deny `openat` outright — the property
  that caps their filesystem — which is only sustainable while nothing renders
  real text or persists data. So storage (the `localStorage`/`IndexedDB`
  stand-in) and the font service run outside the zygote with a `baseline +
  openat` filter. That grants `openat` on *any* path, because seccomp sees only
  the syscall number, never the path pointer — so **Landlock** confines *which*
  paths: each service declares a ruleset of `(directory, rights)` and the kernel
  enforces it, scoping storage to its own dir and the font service to its one
  read-only file. Storage is additionally keyed by the `(zone, origin)` the
  *engine* stamps (never a message claim), and the renderer's key is hashed into
  the filename rather than spliced into a path — so path traversal is guarded at
  the application level *and* by the kernel. It is also **byte-bounded**: each
  value is capped (`MAX_VALUE_BYTES`) and the store is held to a lifetime budget
  (`MAX_STORE_BYTES`) tracked with an in-memory running counter — accounting an
  overwrite as a delta, and needing no directory-enumeration syscall — so a
  renderer can't fill the host disk one bounded `Set` at a time. Landlock is
  best-effort: a kernel without it degrades to seccomp + the hashing, rather
  than refusing to start.
  **GPU and audio are intentional stubs, by scope**: real processes with the
  correct device filter (`baseline + openat + ioctl`) and empty net/IPC/UTS
  namespaces, which proves the security-relevant thing — GPU/audio can run *out of
  process and confined*. The actual graphics work is deliberately out of scope: a
  PoC has no hardware to drive, and compositing is not a security demonstration.
  The honest caveat (inherent to real GPU work, not a gap to close) is that
  `ioctl` is a large surface seccomp constrains poorly, so the isolation shown is
  the process boundary, not a tight filter.

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
  the renderer; identity fields inside messages are never trusted. A renderer
  only ever serves its own origin: a **cross-origin navigation swaps the
  renderer** (site isolation) — the engine tears the old one down and brings up
  a fresh process bound to the new `(zone, origin)`, the way Chromium changes
  `RenderFrameHost`, rather than letting one process serve two origins. The
  teardown is distinguished from a crash (the tab's gate is closed first) so the
  reused tab id never surfaces a spurious `TabCrashed`.
- **HttpOnly cookies never reach a renderer.** Cookies carry an `http_only`
  flag; the net component receives all of a request's cookies to attach to the
  outbound fetch (it must — that's how authenticated requests work), but a
  renderer asking for `document.cookie` gets only the non-HttpOnly ones. So an
  exploited `example.com` renderer never sees `example.com`'s session token —
  it travels engine → net and skips the renderer's address space entirely.
- **Cross-origin subresources go through Opaque Response Blocking (ORB).** A
  renderer's *document* fetch (`NeedFetch`) is same-origin only, but real pages
  load cross-origin subresources (images, scripts, styles, fonts), so a
  `NeedSubresource` request *may* be cross-origin. That is safe only because the
  trusted side decides what bytes the renderer may *read*: site isolation keeps
  each origin in its own process so a Spectre gadget reads only its own address
  space, and ORB is what keeps cross-origin secrets from getting into that space
  to begin with. The engine resolves the destination origin and attaches *its*
  cookies (never the renderer's), then the net component classifies the response
  and applies ORB (`src/orb.rs`): a same-origin or CORS-approved response is
  readable; a cross-origin no-cors *embeddable* type (image/script/CSS/font) is
  delivered **opaque** (usable, not readable as data); a cross-origin *data* type
  (HTML/JSON/XML) or anything not clearly embeddable is **blocked** — its bytes
  never enter the renderer. Cross-origin *navigation* is handled by swapping the
  renderer (above); ORB is the separate mechanism for cross-origin
  *subresources*, which a page loads without navigating.
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
  Hostnames resolve through a pluggable resolver seam (the PoC's is synthetic
  and offline; a deployment selects `SystemResolver`): every resolved IP is
  classified and the survivor is *pinned* as the address to connect to, so there
  is no second lookup left to poison (DNS rebinding). **Redirects are followed
  with the same classification re-run on every hop** — an open redirect to
  `169.254.169.254` is refused even when the entry URL was public, and the chain
  is bounded so a redirect loop terminates as a refusal. A redirect that leaves
  the original origin drops the request's cookies rather than leaking one
  origin's session token to another host.
- Renderers are **sandboxed at the OS level** (Linux): after connecting their
  IPC link, they install a default-deny seccomp-BPF **allowlist** permitting
  only a curated baseline (I/O on existing fds, memory, futex, signals, time).
  A renderer — even one fully code-exec'd by an exploit — physically cannot
  open a socket, an io_uring instance, a file, or a subprocess: the attempt
  traps to `SIGSYS`, is logged with the syscall number, and kills the process.
  See `src/sandbox/linux.rs`. The net component gets the same baseline plus the
  socket family.
- Children run under **OS resource caps** the engine sets at spawn (Linux):
  `RLIMIT_DATA` (512 MiB committed heap — the *heap*, not the address space, so a
  future JIT's multi-GiB virtual cage still fits) with a generous 16 GiB
  `RLIMIT_AS` sanity ceiling, plus `RLIMIT_NOFILE` and `RLIMIT_CORE=0`. seccomp
  caps *what* a child may do; these cap *how much*, so a compromised renderer
  can't exhaust host memory/fds — an over-allocation aborts that process, not the
  machine — and a crash won't dump a core full of secrets. On top of the rlimits,
  the engine places each spawned child in its own **cgroup v2 `memory.max`** where
  the platform allows it (a systemd scope with `Delegate=yes`, or root) — a true
  RSS bound whose OOM kill is scoped to the offending child rather than the global
  killer reaching the broker; it degrades to rlimits-only in a shared scope. This
  is the parent-side `confine_spawned_child` seam, the Linux analogue of the
  Windows job-object memory cap.
- **Crash reporting** without a core dump or `ptrace`: `RLIMIT_CORE=0` stops
  cores, `PR_SET_DUMPABLE=0` and the broker deny-list stop any *other* process
  reading a crashed one — so, like Crashpad on Linux, the crashing process
  **self-captures**. A handler for `SIGSEGV`/`SIGABRT`/`SIGBUS`/`SIGILL`/`SIGFPE`
  (on an alternate stack, so a stack overflow can still run it) writes a one-line
  report — signal + faulting *address*, **no memory contents**, so it can't leak
  the cookie jar even from the broker — then restores `SIG_DFL` and returns, so
  the fault re-executes and the process still dies with its signal (the engine's
  crash detection is unchanged). Uses only `write` + `sigaction`, both already on
  every filter.
- **Crash-loop guard**: an origin that crashes its renderer 3+ times in 30 s
  (per `(zone, origin)`) is refused a fresh one — `OpenTabFailed`/`NavigationFailed`
  instead of respawning into a loop — with the backoff expiring as the crashes age
  out. Bounds respawn *churn*, the complement to the live-renderer cap.
- On the IPC side, the shared event-loop inbox is **bounded per source**. Every
  component (each renderer, the net process) may have at most
  `MAX_QUEUED_PER_SOURCE` messages queued-but-unprocessed: its reader thread
  takes a permit before forwarding a message and the loop returns one after
  handling it. When a source runs out of permits its reader stops draining that
  socket, so the OS backpressures the component itself. Because the bound is
  *per source*, one compromised renderer flooding any message type pins a fixed
  slice of engine memory and can't crowd out other tabs — without it, a flood
  grows the engine ~90 MB/s to OOM; with it, engine RSS stays flat. In-flight
  fetches are *additionally* bounded per tab (`MAX_INFLIGHT_FETCHES`), and
  decodes per tab (`MAX_INFLIGHT_DECODES`, since each forks a process).
- The engine also caps the **total** live renderer count (`MAX_RENDERERS`).
  The per-tab bounds limit what one renderer costs; nothing else limits how
  many renderers a hostile page (`window.open` in a loop) or a buggy embedder
  can bring into being. Past the cap an `OpenTab` is refused
  (`OpenTabFailed`) rather than spawning another process, so tab count can't
  become a PID/memory exhaustion vector — the same finite ceiling Chromium's
  process limit imposes.
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
  userinfo/trailing-dot bypasses), redirect following (per-hop SSRF re-check,
  the hop-count bound, and cookies not crossing an origin), Opaque Response
  Blocking (same-origin/CORS readable, cross-origin embeddable opaque,
  cross-origin data blocked, and a cross-origin redirect forcing ORB), the
  cookie broker (`(zone, origin)`
  partitioning + HttpOnly hiding), IPC frame round-trip and oversized-length
  rejection, the per-source backpressure `Gate`, the storage quota admission
  (per-value cap, overwrite-as-delta, saturating arithmetic), and origin
  parsing. The
  single-process engine is also driven end to end (open → navigate → frame →
  close → shutdown, the **cross-origin renderer swap** committing the new origin
  and rendering it, unparseable URL) — the broker/policy code is identical in
  both modes, so this exercises the real thing.
- **Integration tests** (`tests/integration.rs`) run the actual built binary:
  multi- and single-process runs render and shut down cleanly (the default run
  also performs a cross-origin renderer swap with real child processes and no
  spurious crash), unknown args are
  rejected, tiles arrive via shared memory (multi-process) or in-band copy
  (single-process) and byte-match the expected pattern either way, the tile
  bench completes on both transports, large fetch bodies stream through the
  ring (multi-process) or fall back in-band (single-process) and byte-match
  the producer's pattern either way, the stream bench completes on both
  transports, and (Linux) the children both *announce* and *enforce* their
  seccomp sandbox — the `selftest` probes confirm that making memory
  executable (`PROT_EXEC`), opening a socket, and any `fcntl` beyond the seal
  commands are each killed by `SIGSYS`, that the fork server can fork but a
  `clone` unsharing a namespace is killed, that a filesystem service's `openat`
  is scoped by Landlock, and that the **broker's** Landlock confines its writes
  to the temp dir (a write outside is `EACCES`, with a control proving it worked
  before lockdown) — while the sealed-memfd tile dance and the ring
  produce/consume dance both survive. The `shm` and `ring` unit
  tests additionally pin the consumer-side refusals: unsealed fds, undersized
  fds, absurd dimensions/lengths, corrupt ring cursors, aborted and truncated
  streams — plus a two-thread ring round-trip that wraps the window 256×.

Two properties are checked by hand rather than in `cargo test`, as they need
external tooling: the fork server forking renderers *without* exec (an `execve`
strace shows only `fork-server`/`net-daemon`, never `renderer`) and the
per-source inbox bound holding engine RSS flat under a message flood (RSS
sampling: ~2.8 MB steady vs. ~90 MB/s growth without it). The `Gate` unit test
covers the bounding mechanism itself deterministically.

### Fuzzing

The three surfaces where **untrusted bytes meet a parser** have `cargo-fuzz`
targets in `fuzz/`, each importing the real code from the library crate:

- `decode_image` — `decoder::decode`, the image parser (the libwebp
  CVE-2023-4863 lineage: a header that lies about its dimensions).
- `ipc_frame` — `ipc::recv_msg` for the frames a *compromised child* sends the
  broker, which deserializes them in its own address space with full authority
  over every secret (the broker's deny-list seccomp removes escalation syscalls
  but not this data reach — the sharpest edge in the model, see the sandbox
  section).
- `ssrf_url` — `ip_utils::resolve_and_pin`, the URL/host/IP-literal parsing that
  gates every outbound fetch; a mis-parse there is an SSRF.

```sh
cargo +nightly fuzz run decode_image     # or ipc_frame / ssrf_url
```

Each target's contract is *total*: any input returns `Ok`/`Err`, never panics
or reads out of bounds. So that the property is also checked in ordinary CI
without nightly, each parser additionally carries a deterministic
`*_never_panics_on_arbitrary_*` unit test — a seeded xorshift stand-in for the
fuzzer (50 000 inputs each) that pins a regression floor; the `fuzz/` targets
explore far more.

## Layout

| File | Contents |
|------|----------|
| `src/events.rs` | Public vocabulary: `EngineCommand`, `TabCommand`, `EngineEvent`, `TabId`, `Tile` |
| `src/engine.rs` | `start(mode)`, `EngineHandle`, the event loop (broker + policy), `Spawner` |
| `src/ipc.rs` | `Endpoint` tx/rx halves (channel/local transports), wire messages, bincode framing, `SCM_RIGHTS` fd-passing (Linux) |
| `src/channel/` | Transport seam: the duplex byte channel a link runs over — `unix.rs` (socketpair), `windows.rs` (anonymous pipe pair) |
| `src/net_daemon.rs` | Net component: `serve` loop, (synthesized) fetching, redirect following, ORB enforcement |
| `src/orb.rs` | Opaque Response Blocking: the pure decision for what cross-origin response bytes may reach a renderer |
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
| `src/lib.rs` | Library crate: `pub` modules the binary, tests, and fuzz targets all build on |
| `src/main.rs` | Binary: child-role dispatch for re-exec + minimal event-driven usage |
| `fuzz/` | `cargo-fuzz` targets over the untrusted-input parsers (`decode_image`, `ipc_frame`, `ssrf_url`) |
| `tests/integration.rs` | End-to-end tests running the built binary (both modes + sandbox) |

## Shortcuts taken (what a real implementation needs instead)

The security *mechanisms* are real (see the isolation section); what's
simplified is the surrounding browser. What each entry below still needs:

- **Sandboxing**: the seccomp filter is production-shaped (fail-closed
  allowlist, SIGSYS-kill-on-violation with the blocked syscall reported, W^X via
  `PROT_EXEC` argument-filtering), and
  renderers additionally run in an empty **network namespace** (plus **IPC**,
  **UTS**, and **PID** namespaces) — unshared on the fork server at spawn and
  inherited by every renderer it `fork()`s, so "a renderer cannot reach the
  network" no longer rests on the syscall allowlist alone. The two layers fail
  independently: an allowlist gap is survivable when the namespace has no
  interfaces to connect through. The net component is the one role that keeps the
  host netns; the IPC and UTS namespaces are defense in depth for properties
  seccomp also covers (no shared System V IPC, its own hostname). The **PID**
  namespace is the same kind of belt-and-suspenders for `kill`/`ptrace`'s absence
  — a renderer can't even *name* the broker or host processes by pid. Because
  `unshare(CLONE_NEWPID)` places the caller's *children* (not the caller) in the
  new namespace, the fork server's renderers share one, and the fork server pins
  its PID 1 with a do-nothing placeholder so one renderer exiting can't tear the
  namespace down and `SIGKILL` its siblings (fault isolation). Per-renderer PID
  namespaces are blocked by the same `uid_map`-less-userns constraint as the mount
  namespace; all of this is best-effort and falls back to the rest where a kernel
  refuses `CLONE_NEWPID`. Separately, every process
  (engine included, in both modes) clears its **dumpable** flag, so other
  software running as the same user cannot `ptrace`-attach or read
  `/proc/<pid>/mem` — the engine's cookie jar is the obvious target, and this is
  the inbound direction that seccomp has no say over. It is set after `execve`,
  which resets the flag; it survives `fork`, so renderers inherit it from the
  fork server. Filesystem restriction with **Landlock** is used by the
  filesystem services (storage, font) to path-confine their `openat`, and the
  **broker** gets a loose Landlock too (read/exec anywhere, write only the temp
  dir) plus a **deny-list seccomp filter** (allow by default, `SIGSYS` on the
  escalation syscalls it never uses — `ptrace`, kernel-module loading, `kexec`,
  `bpf`, `mount`/`setns`). Renderers also get a **PID** namespace now (shared
  across the fork server's renderers, with a pinned PID-1 placeholder so one
  renderer exiting can't `SIGKILL` its siblings) — so a renderer can't name the
  broker or host by pid. *Per-renderer* PID namespaces and an empty-root **mount**
  namespace remain deliberately *not* added, both blocked by the same concrete
  reason rather than merely unimplemented: each needs capability over a namespace
  owned by a user namespace the fork server does not control, and its
  deliberately-unmapped (`uid_map`-less) user namespace confers none — while
  writing a `uid_map` to fix that is blocked *both* by AppArmor on modern hosts
  and by the broker Landlock (`/proc/self/uid_map` is outside the temp dir). It is
  documented at `isolate_network` in `src/sandbox/linux.rs`, and seccomp's
  `open`/`openat` and `kill`/`ptrace` denials cover the properties regardless.
  Also still wanted: a per-arch seccomp baseline tested across libc/kernel
  versions. And several of the tightest limits here (W^X, no renderer threads,
  the 512 MiB `RLIMIT_AS`, zero file opens) are enforceable only because this
  renderer is a stub — a real JIT-and-media renderer relaxes each and compensates
  elsewhere; see *What a real renderer would force open* above.

  **Platform status.** Linux is the reference implementation: seccomp, empty
  net/IPC/UTS/PID namespaces, rlimits, non-dumpable processes, broker Landlock + a
  seccomp deny-list, best-effort per-child cgroup v2 `memory.max`, self-captured
  scrubbed crash reports, 22 probes.
  macOS runs a Seatbelt `(deny default)`
  profile with 13 probes — including **path-scoped file services** (storage/font
  get `subpath` read/write grants for their own directory plus a broad
  `file-read-metadata` so path lookup resolves, while contents outside the scope
  stay unreadable) and a **denied Mach bootstrap** (no `mach-lookup` reach to
  WindowServer/launchd services). Windows spawns over a pair of anonymous pipes (see
  `src/channel/`) and installs **process mitigation policies** — no dynamic
  code (the W^X analogue), no child processes, no injection extension points,
  plus win32k lockdown — with 4 probes, plus the parent-side access controls
  below.

  Windows has **both halves of a sandbox** now. The self-applied half is the
  mitigation policies above (plus low integrity and a job-object memory cap).
  The parent-side, object-confining half is an **AppContainer** — the "lowbox"
  token UWP apps and Chromium's renderer run under — attached at `CreateProcess`
  via a `SECURITY_CAPABILITIES` attribute: a **per-role** container gives a
  renderer **no network and no broad file access**, the net component
  **`internetClient`**, and each filesystem service access to **only its own
  path** (with a Low-integrity relabel so the lowbox can write it) — the same
  renderer/net split and per-service file scoping Linux gets from seccomp+netns
  and Landlock. It is **env-gated** (`GOSUB_WIN_APPCONTAINER`) rather than
  default-on for one concrete reason: a lowbox process can only load images the
  filesystem grants an app-package SID, so the binary must sit at an
  app-package-accessible install location (`C:\ProgramData`, `C:\Program Files`)
  — exactly what a real installer targets, and what CI's `target\` dir is not.
  With that, it is validated end to end on Windows 11 (registered containers,
  the capability split, and storage/font round-tripping under the lowbox). The
  *restricting-SID* token stays out for the same image-loading reason; the
  AppContainer is what actually clears that wall. See `src/sandbox/windows.rs`.

  Note the netns is obtained via `CLONE_NEWUSER | CLONE_NEWNET` (an unprivileged
  `CLONE_NEWNET` alone needs `CAP_SYS_ADMIN`) and the uid map is deliberately
  left unwritten, so children run as the overflow uid. This makes multi-process
  mode require unprivileged user namespaces, the same way it already requires
  seccomp — hosts without them use `--single-process`.
- **Fetching**: synthesized responses instead of real HTTP; the net component
  handles one request at a time (the engine doesn't block on it, but a real
  daemon would fetch concurrently — with the ring transport that matters
  more, since one slow-draining body stream now occupies the component until
  it completes or hits the 5 s stall timeout). The SSRF filter resolves through
  a resolver seam and pins the result (the PoC's resolver is synthetic; a
  deployment selects `SystemResolver`), and redirects are followed with the
  classifier re-run on every hop — but real DNS and real HTTP are still stubbed.
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
  too, closing the HTTPS→HTTP secure-cookie downgrade. A cross-origin
  navigation (including an `https:`→`http:` scheme change) **swaps the
  renderer** rather than being refused, which is the real site-isolation
  mechanism — but a *simplified* one: it swaps a single-frame tab, not the
  frame tree, so the genuinely hard parts (out-of-process iframes,
  `document.domain` agent clusters, BrowsingInstances, back-forward cache) are
  still absent. Also still not a real URL parser (no IDNA, no userinfo; the
  SSRF filter's `host_of` remains the deliberately-hostile one — a real engine
  would share one implementation).
- **Fork server**: it is `exec`'d fresh (one exec) rather than forked from the
  engine early to inherit the *engine's* warm libraries; the modeled behavior
  is renderers fork-without-exec from a warm process. It confines *itself* like
  any other role — its own seccomp filter (a superset of the content baseline:
  `fork`/`clone`/`wait4`/`prctl`/`seccomp`), the `clone3`→`ENOSYS` + plain-fork
  `clone` hardening so it cannot unshare a namespace or thread/VM-share via
  `clone`, empty net/IPC/UTS namespaces, and non-dumpable — all inherited by the
  renderers it forks — and it is minimal and secret-free besides. Linux only —
  `fork()`-without-exec + the Rust runtime relies on `fork()` semantics.
  Elsewhere renderers fall back to direct fork+exec.
