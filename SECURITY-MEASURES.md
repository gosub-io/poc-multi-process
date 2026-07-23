# Security measures in this PoC

An enumeration of every security mechanism this proof of concept actually
implements, split into **general** (architecture and policy, identical on all
platforms) and the three OS backends (**Linux**, **Windows**, **macOS**), plus
the fallback for everything else.

Status is marked as:

- **Applied** — implemented and in effect.
- **Partial** — implemented, but with a documented gap.
- **Absent** — deliberately not implemented; listed so the guarantee is not
  over-read. Collected in [§7 Known gaps](#7-known-gaps).

Everything below applies to **multi-process mode**. In single-process mode the
policy checks still run, but with components as threads inside the engine there
is no boundary behind them (`--single-process` / `--no-default-features`).

---

## 0. Process roles and what confines each

| Process | Extra capability over content baseline | OS parent | Confinement |
|---|---|---|---|
| engine (broker) | everything — spawns, sockets, cookie jar | — | Landlock (writes confined to temp) + seccomp **deny-list** (denies `ptrace`/`kexec`/`bpf`/`mount`/`setns`/…) + `deny_debugger_attach` |
| fork server (zygote, Linux) | `fork`/`wait4`, `prctl`/`seccomp` for children | engine | seccomp superset of content baseline, empty net/IPC/UTS namespaces, non-dumpable; its forked renderers share a **PID** namespace (pinned PID-1 init) |
| renderer (per `(zone, origin)`) | none | fork server | content baseline + inherited net/IPC/UTS/PID namespaces |
| decoder (ephemeral, per image) | none | fork server | content baseline (renderer lockdown reused) |
| net component | sockets (outbound only) | engine | baseline + socket family; **keeps** host netns |
| storage service | `openat` | engine | baseline + `openat` + Landlock (storage dir, rw) |
| font service | `openat` | engine | baseline + `openat` + Landlock (one file, ro) |
| audio / gpu services (stubs) | `openat` + `ioctl` | engine | baseline + device syscalls, empty net/IPC/UTS namespaces |

Every engine-spawned child (services + the fork server) is additionally placed in
its own **cgroup v2 `memory.max`** where the platform allows it (best-effort — a
delegated systemd scope or root; see §2.5). The governing rule: **the zygote may
only parent processes strictly less privileged than itself.** Its filter,
namespaces and non-dumpable flag are inherited and only ever narrow — so any role
needing a capability the zygote gave up (files, devices, network) is spawned
fork+exec from the engine instead, with its own wider filter.

---

## 1. General (all platforms)

### 1.1 Process & privilege architecture

| Measure | Where | Status |
|---|---|---|
| Capability split across processes — network, filesystem, devices and rendering each live in a different process | `engine.rs`, `sandbox/mod.rs` | Applied |
| **Site isolation**: one renderer per `(zone, origin)`; the same origin in two zones is two processes with independent partitions | `engine.rs` | Applied |
| **Ephemeral image decoder** — one process decodes exactly one image and exits, so a decoder can never see a second origin's data | `decoder.rs` (`serve_one`) | Applied |
| Renderers hold **no secrets** — no cookies, no network handle; they can only send IPC messages | `renderer.rs` | Applied |
| **Cross-origin navigation swaps renderers** — a cross-origin navigation tears down the tab's renderer and brings up a fresh process bound to the new origin (Chromium's `RenderFrameHost` change), so two origins never share a process | `engine.rs` | Applied |
| Crash containment — a dead renderer surfaces as `TabCrashed` for that tab only; engine and other tabs continue | `engine.rs` | Applied |
| **Crash-loop guard** — an origin that crashes its renderer `CRASH_LOOP_THRESHOLD`+ times within a window is refused a fresh one (`OpenTabFailed`/`NavigationFailed`) instead of being respawned into a loop; the backoff is scoped to `(zone, origin)` and expires with the window | `engine.rs` (`CrashTracker`) | Applied |
| Fork server is **minimal, single-threaded and secret-free**, and is started *before* the engine loads any cookies | `fork_server.rs` | Applied |

### 1.2 Broker policy (the engine event loop *is* the boundary)

| Measure | Detail | Status |
|---|---|---|
| **Ambient identity** — `(zone, origin)` comes from the engine's own `Tab` record; identity fields inside messages are never trusted | `tab_request` | Applied |
| Same-origin **fetch** check | `may_fetch(tab.origin, url)`; refusal prevents a renderer naming an attacker URL and having the engine attach *this* origin's cookies to it | Applied |
| Same-origin **cookie** check | `NeedCookies` compared against `tab.origin`, not the message | Applied |
| **HttpOnly cookies never reach a renderer** | `attachable_cookies` (all, → net) vs `visible_cookies` (non-HttpOnly, → renderer). The session token travels engine → net and skips the renderer's address space | Applied |
| **Opaque Response Blocking (ORB)** — the net/engine decides what cross-origin subresource bytes a renderer may *see*: same-origin readable, cross-origin embeddable types delivered opaque, cross-origin data types (HTML/JSON) blocked unless a CORS grant applies | `orb.rs`, `net_daemon.rs` | Applied |
| Cookie jar partitioned by `(ZoneId, origin)` | one zone can never touch another's partition | Applied |
| Origin canonicalization over the full `scheme://host[:port]` tuple, default ports folded, host/scheme lowercased, non-numeric port rejected | `origin_of` — closes the HTTPS→HTTP secure-cookie downgrade; an `https:` renderer cannot be navigated to `http:` | Applied |
| Storage partition key stamped by the engine | `NeedStorage` is forwarded with `tab.zone`/`tab.origin`, never a message claim | Applied |
| SSRF policy centralized in the one process allowed to open sockets | `net_daemon.rs` + `ip_utils.rs` — no renderer bug can bypass it | Applied |

### 1.3 SSRF classification (`ip_utils.rs`)

Classifies the **numeric** address, so alternate spellings do not help:

- Loopback, private (incl. `172.16/12`), link-local & cloud-metadata
  (`169.254.169.254`), CGNAT, `0.0.0.0/8`, multicast, class E.
- Special-purpose registry blocks: TEST-NETs, benchmarking, `192.0.0.0/24`,
  6to4 relay.
- IPv6 equivalents incl. unique-local and link-local.
- Alternate IP encodings (`http://2130706433/`, `0x7f.1`, octal), IPv4-mapped
  IPv6, NAT64 / IPv4-compatible embeddings (`64:ff9b::7f00:1`, `::127.0.0.1`).
- Userinfo confusion (`http://real.com@127.0.0.1/`) and trailing dot.
- Fails **closed** on any blocked answer.
- **Re-run on every redirect hop**, with the resolved IP pinned per hop: an open
  redirect to an internal address (`302 → http://169.254.169.254/`) is refused
  even when the entry URL was public — the bypass an entry-only check misses.

Knowingly not classified: subnet-directed broadcast (`x.y.z.255`) — it depends
on the local netmask. Hostname resolution and DNS-rebinding pinning are
**Absent** (see §7).

### 1.4 IPC hardening

| Measure | Detail | Status |
|---|---|---|
| **Inherited descriptor is the authentication** — a `socketpair(2)` (Unix) / anonymous pipe pair (Windows) passed at spawn | No rendezvous path on disk, no auth token on argv (readable via `/proc/<pid>/cmdline`), no `accept()` race, unforgeable | Applied |
| Every other engine fd stays `CLOEXEC`; the one descriptor a child should inherit is un-marked **inside the forked child** (`pre_exec`), not in the parent | so a concurrent spawn never leaks another renderer's channel | Applied |
| Length-prefixed frames with a **16 MiB** cap checked *before* allocating | `MAX_FRAME_LEN` in `ipc.rs` — a corrupt length prefix cannot force an unbounded allocation | Applied |
| Closed wire enums + bincode (no type-directed dispatch, unlike pickle / Java serialization / `serde_yaml` tags) | narrow deserialization surface, and the untrusted-input parsers (`ipc::recv_msg`, `decoder::decode`, the SSRF/URL parser) carry `cargo-fuzz` targets (`fuzz/`) | Partial |
| `SCM_RIGHTS` receive walks **all** control messages, adopts every fd the kernel installed, and enforces exactly-one | a peer stuffing extra fds gets a refusal and all fds closed, instead of leaking descriptors into the engine's fd table | Applied |
| Received fds are `MSG_CMSG_CLOEXEC` and wrapped in `OwnedFd` | no leak on an early return | Applied |
| Dynamic-loader injection vectors stripped from the child environment before `exec` (`LD_*`, `DYLD_*`) | otherwise attacker-supplied library code runs *before* the child reaches its own lockdown | Applied |

### 1.5 Resource and DoS bounds

| Bound | Value | Purpose |
|---|---|---|
| `MAX_QUEUED_PER_SOURCE` | 64 messages | Per-source inbox gate: a reader thread takes a permit before forwarding and the loop returns one after handling. Out of permits ⇒ the reader stops draining that socket ⇒ the OS backpressures the component. Because it is **per source**, one flooding renderer pins a fixed slice of engine memory (measured: engine RSS flat vs ~90 MB/s growth to OOM without it) |
| **global renderer-process cap** | ceiling on live renderers | a page looping `window.open`, or an embedder bug, cannot fork renderers without bound (the per-tab caps bound *work per tab*, not tab count) |
| **crash-loop backoff** | `CRASH_LOOP_THRESHOLD` = 3 crashes / 30 s per `(zone,origin)` | an origin that reliably kills its renderer (a decompression bomb, an exploit-probe) is refused a fresh one instead of respawned forever — bounds respawn churn, not just live count |
| **per-`(zone,origin)` storage byte quota** | budget enforced in `storage.rs` | a renderer cannot fill the disk via `Set` |
| `MAX_INFLIGHT_FETCHES` | 32 per tab | A renderer cannot pile up fetches |
| `MAX_INFLIGHT_DECODES` | 8 per tab | A renderer spamming `NeedDecode` cannot fork processes without limit |
| `MAX_FRAME_LEN` | 16 MiB | Per-message ceiling |
| `MAX_TILE_DIM` | 2048 (⇒ 16 MiB) | Shared memory never lets a renderer pin *more* engine memory per message than the socket path could |
| ring `MAX_CAPACITY` / `MAX_BODY_LEN` | 64 MiB / 128 MiB | Bounds on the streaming transport |
| ring `STALL_TIMEOUT` | 5 s of zero progress | Both sides bound their patience: a dead or deliberately-stalling peer costs seconds and only that stream, never the component |

### 1.6 Hostile-input parsing discipline

**Image decoder (`decoder.rs`)** — the header is a *claim*, checked against
reality: magic bytes, `MAX_DECODE_DIM = 4096` and non-zero on both dimensions
checked *before* the multiply, `checked_mul` for `w * h * 4`, and the pixel
byte count must match **exactly**. Everything malformed is rejected.

**Shared-memory tiles (`shm.rs`)** — *validate the fd, not the message*:

- Producer **seals before sending**: `F_SEAL_SHRINK | F_SEAL_GROW |
  F_SEAL_WRITE | F_SEAL_SEAL`. The kernel refuses `F_SEAL_WRITE` while any
  writable mapping exists, so a sealed fd *proves* no writer remains anywhere,
  and the seals can never be lifted.
- Consumer bounds the claimed dimensions, requires the seals to actually be
  present (`F_GET_SEALS`), and `fstat`s the fd's **real** size before mapping.
  `F_SEAL_SHRINK` makes that check TOCTOU-free — the fd cannot be shrunk after
  validation to `SIGBUS` the engine.
- A tile that fails validation is a protocol violation: the engine drops the
  link (→ `TabCrashed`).
- Lifecycle: `MFD_CLOEXEC`, producer's copy closed right after sending,
  consumer's closed as soon as the mapping exists.

**Streaming ring (`ring.rs`)** — the trust contract shifts from seals to
discipline, per transport role:

- The kernel still guarantees *size* (`F_SEAL_SHRINK|GROW` at creation — unlike
  `F_SEAL_WRITE` these coexist with writers, so the `fstat` check stays
  TOCTOU-free and no read can `SIGBUS`).
- Contents and cursors are treated as **hostile**: each side copies the shared
  read/write cursors to locals and validates them against capacity before
  touching a byte (a corrupt cursor is a detected protocol violation, not an
  OOB read); offsets are reduced mod capacity only *after* that check.
- The consumer reads **single-pass** — every byte copied out exactly once,
  never re-read — the discipline that replaces immutability.
- A producer that dies mid-stream is caught by an abort flag; a truncated
  stream (fewer bytes than promised) is an error.
- `F_SEAL_SEAL` stops the peer from adding seals.

**Storage keys (`storage.rs`)** — `openat` takes a path pointer seccomp cannot
inspect, so no attacker-controlled bytes ever reach a path: the
`(zone, origin, key)` tuple is composed **with length prefixes** (so distinct
tuples cannot alias) and hashed; the filename is pure `[0-9a-f]` hex. A key of
`../../../../etc/passwd` cannot escape the directory. Landlock is the second,
kernel-level guard.

**Font service (`font.rs`)** — returns only *derived* data (metrics), never the
font bytes, so a renderer never handles the file.

---

## 2. Linux (the reference implementation)

### 2.1 seccomp-BPF — default-deny allowlist

- **Allowlist, not a denylist**: the syscalls a component legitimately needs are
  enumerated; everything else is a fatal `SIGSYS` (not `EPERM` — a killed process
  cannot probe the sandbox and adapt). Fail-closed: a syscall never considered (a
  new one, or an io_uring-based networking bypass) is denied for free.
- **The default action is `SECCOMP_RET_TRAP`**, not `KillProcess`: a handler names
  the offending syscall on stderr (`[sandbox] SIGSYS: blocked syscall #N —
  terminating`) and then re-raises `SIGSYS`, so the process still dies with the
  same signal — you just learn *which* call it was ("renderer tried `openat`
  (#257), killed"). Its one added privilege is `tgkill`, argument-filtered to
  SIGSYS-to-self.
- **Startup is fail-closed**: a component that cannot install its filter aborts
  rather than run unconfined. Multi-process mode therefore *requires* seccomp.
- Installed **after** the IPC link is connected and split, so the socket/dup work
  happens before the filter exists.

Per-role filter sets (`sandbox/linux.rs`):

| Role | Filter |
|---|---|
| renderer, decoder | `BASELINE` only |
| net component | `BASELINE` + `socket`, `socketpair`, `connect`, `get/setsockopt`, `getsockname`, `getpeername` |
| storage, font | `BASELINE` + `openat` |
| audio, gpu | `BASELINE` + `openat` + `ioctl` |
| fork server | `BASELINE` + `fork`/`clone`/`clone3`, `wait4`, `prctl`, `seccomp`, `set_robust_list`, `set_tid_address` |

Deliberately absent from `BASELINE`: `socket`/`connect`, `openat`,
`execve`/`clone`, `io_uring_*`, `ptrace`.

Deliberately absent from the **net** extras: `bind`/`listen`/`accept`/`accept4`
— a compromised net component can originate connections but cannot become a
local listening backdoor / C2.

**`clone3` → `ENOSYS`** (fork server): `clone3` cannot be argument-filtered (its
flags live in a memory struct seccomp cannot dereference), so a stacked pre-filter
returns `ENOSYS` for it, making glibc's `fork()` fall back to the register-based
`clone` — which *is* argument-filtered (see §2.2). The standard Chromium/systemd
technique; inert on musl / old glibc, which never issue `clone3`.

**Broker (engine) seccomp — a deny-list, not an allowlist.** The engine execs
helpers, spawns threads, and opens files/sockets, so a renderer-style allowlist
does not fit (Chromium's *browser* process is likewise not allowlisted). Instead
it runs default-**allow** with a `Trap` on the post-compromise escalation
primitives it never needs: `ptrace`/`process_vm_*`, kernel-module loading
(`init_module`/`finit_module`/`kexec_*`/`bpf`), the LPE surfaces
(`perf_event_open`/`userfaultfd`/keyring/`kcmp`), and namespace/mount escapes
(`setns`/`mount`/`umount2`/`pivot_root`/`swapon`/`reboot`). Every denied syscall
is one **no child needs either**, since this filter is inherited before each child
installs its own stricter allowlist. Best-effort (`lock_down_broker`).

### 2.2 Argument filtering

| Rule | Effect |
|---|---|
| `mmap`/`mprotect` allowed only when `PROT_EXEC` is clear (`MaskedEq(PROT_EXEC) == 0` on arg 2) | **W^X** — a renderer can never turn writable memory executable, the step most memory-corruption chains need to run injected code. `mremap` preserves an existing mapping's protection, so it cannot introduce exec |
| `fcntl` allowed only for `F_ADD_SEALS`, `F_GET_SEALS`, `F_GETFD` | every *mutating* command — `F_DUPFD` (fd fabrication), `F_SETFL`, locks — is a fatal `SIGSYS` |
| Fork server only: additionally `F_DUPFD_CLOEXEC`, and `F_SETFD` **only with `FD_CLOEXEC`** | permits *setting* close-on-exec but never clearing it (which would leak a descriptor across an exec) |
| Fork server only: `clone` allowed only for a **plain fork** (`MaskedEq(DANGEROUS) == 0` on arg 0, where `DANGEROUS` = `CLONE_NEW*` \| `CLONE_THREAD` \| `CLONE_VM`) | once `clone3` is `ENOSYS`'d, glibc's `fork()` reaches the kernel as `clone` with flags in a register we can inspect — so even a subverted fork server cannot unshare a namespace or thread/VM-share via `clone` |

### 2.3 Landlock — path-level filesystem confinement

seccomp sees only the syscall number and registers, never the path a pointer
points at, so `openat` is all-or-nothing. Landlock supplies the missing half:

- Each filesystem service declares a ruleset of `(directory, rights)`: storage
  → its own dir (writable), font → its one file (read-only).
- Applied **before** seccomp, so its own syscalls and the `O_PATH` anchors run
  unfiltered; sets `PR_SET_NO_NEW_PRIVS` (required by `restrict_self`).
- The ABI version is queried and rights beyond it masked off, so a newer right
  on an older kernel does not make `create_ruleset` reject the whole ruleset.
  Directory-only rights are not set on file paths (would be `EINVAL`).
- **Best-effort**: a kernel without Landlock degrades to seccomp + the key
  hashing rather than refusing to start.

The **broker (engine)** gets a loose Landlock too (`lock_down_broker`): it may
read and execute anywhere (it must, to spawn children and load their libraries),
but may only *write* beneath the temp dir (plus its cgroup subtree, §2.5). So a
broker subverted through the frames it deserializes cannot plant persistence,
overwrite its own binary, or corrupt the user's files.

### 2.4 Namespaces

- Renderers (via the fork server) and every service except the net component run
  in an **empty network namespace** — no interfaces at all, so there is nothing
  to connect to even if a syscall slips through the filter. The two layers fail
  independently.
- Alongside it, **IPC** and **UTS** namespaces (no shared System V IPC / POSIX
  message queues with the host, its own hostname) — cheaper defense in depth for
  properties seccomp also covers.
- A **PID** namespace too, best-effort: because `unshare(CLONE_NEWPID)` is lazy
  (it places the caller's *children* in the new namespace), the fork server's
  forked renderers share one — so a renderer cannot see or signal the broker/host
  by pid even if the filter were bypassed. A shared namespace dies when its PID 1
  exits, `SIGKILL`ing the rest, so the fork server pins PID 1 with a do-nothing
  placeholder and real renderers are PID 2+ (fault isolation preserved).
  *Per-renderer* PID namespaces and an empty-root **mount** namespace are **Absent**
  (§7): both need capability over a namespace owned by a user namespace the fork
  server does not control, which its deliberately `uid_map`-less user namespace
  does not confer.
- All obtained unprivileged via `CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWIPC |
  CLONE_NEWUTS [| CLONE_NEWPID]` in one `unshare` (a bare `CLONE_NEWNET`/`NEWPID`
  needs `CAP_SYS_ADMIN`; pairing with the user namespace gets them unprivileged),
  from `pre_exec`, fail-closed — except `CLONE_NEWPID`, which falls back if a
  kernel refuses it.
- `/proc/self/uid_map` is deliberately **left unwritten**, so the child runs as
  the overflow uid (`nobody`) — strictly better than an identity map, and it
  survives distros that block the map write (Ubuntu 24.04+
  `kernel.apparmor_restrict_unprivileged_userns=1`).

### 2.5 Resource ceilings (`pre_exec`, async-signal-safe)

| Limit | Value | Rationale |
|---|---|---|
| `RLIMIT_DATA` | 512 MiB | Bounds the **committed heap** (brk + writable anon), not the address space: since Linux 4.7 it ignores `PROT_NONE` reservations, so a real JIT's multi-GiB virtual cage still fits while a runaway heap hits `ENOMEM` and aborts *that process*, not the machine. `RLIMIT_AS` (the *virtual* cap this used to be) is the wrong axis — it would kill V8 at init |
| `RLIMIT_AS` | 16 GiB | A generous *virtual* sanity ceiling on top, high enough to clear a JIT cage |
| `RLIMIT_NOFILE` | 128 | A child needs its IPC socket + std streams |
| `RLIMIT_CORE` | 0 | A crash must not dump a core full of cookies/tokens |
| `setpriority` | nice +10 | A compromised child spinning in a loop cannot starve the trusted engine/UI. (A hard `RLIMIT_CPU` is unusable — it counts *cumulative* time and would kill a legitimately long-lived renderer) |

rlimits only ever lower, and raising the nice value needs no privilege, so a
child cannot undo either.

**cgroup v2 `memory.max` (the real RSS bound).** On top of the rlimits, the
engine places each spawned child in its own cgroup with a `memory.max` (+
`memory.high`) ceiling — a true *resident*-memory bound whose OOM kill is **scoped
to the offending child** rather than letting the global killer reach the broker or
a sibling. This is the parent-side `confine_spawned_child` seam (the Linux
analogue of the Windows job-object memory cap). Best-effort via the *leader
pattern*: the broker moves itself into a `…/leader` cgroup so its own cgroup can
delegate `+memory` to a `…/workers` subtree — which works only where the process
owns (or was delegated) its cgroup and is its sole occupant (a systemd scope with
`Delegate=yes`, or root); in a shared scope it degrades to the rlimits above.
Renderers, forked by the fork server, share its cgroup (an aggregate content-pool
bound); per-renderer cgroups need pid plumbing the fork model does not expose.

### 2.6 Anti-debugging (inbound direction)

`prctl(PR_SET_DUMPABLE, 0)` on **every** process, including the engine and
including the single-process build — a same-uid process can otherwise
`ptrace`-attach and read `/proc/<pid>/mem`, which for the engine means the
cookie jar in cleartext. Best-effort (warns, does not abort), since it hardens
against *other software on the host* rather than containing a child. Placement
is load-bearing: set **after** `exec` (which resets the flag), inherited across
`fork`.

### 2.7 Fork-server startup canary

The allowlist is sensitive to the **libc loaded at run time**, not just the
architecture (`fork()` is `clone3` on new glibc, `clone` on old, `SYS_fork` on
musl; glibc resets the robust-futex list, musl registers a TID address; the
endpoint split is `fcntl(F_DUPFD_CLOEXEC)`, not `dup`). So the fork server
**verifies rather than predicts**: at startup it forks one child that performs
exactly what a renderer does between `fork` and its own lockdown, and aborts —
naming the cause — if that child dies on `SIGSYS`. Without it the breakage
appears as every renderer dying moments after spawn, which looks like a
transport bug. The `forkserver-canary-gap` probe runs the canary against a
deliberately crippled filter, so the *detection* is tested, not just the happy
path.

### 2.8 Crash reporting — self-captured, scrubbed, no core, no `ptrace`

A crash report normally needs *some* process to read the crashed one's registers
and memory. Every mechanism for that is deliberately closed here: a renderer is
`PR_SET_DUMPABLE = 0` (nothing may read its `/proc/<pid>/mem`), the broker's
seccomp deny-list forbids `ptrace`/`process_vm_readv`, and `RLIMIT_CORE = 0` stops
core dumps. The resolution — the same one Crashpad uses on Linux — is
**self-capture**: each process installs a handler for the synchronous crash
signals (`SIGSEGV`/`SIGABRT`/`SIGBUS`/`SIGILL`/`SIGFPE`, on an alternate signal
stack so a stack overflow can still run it) that reports its *own* state before
dying. It reads no other process, needs no new privilege, and touches only
`write` + `sigaction` — both already on every filter.

- **Scrubbed by construction.** The report is one line — signal + faulting
  *address* — and carries **no memory contents**: no stack, no heap, no register
  values. A faulting address is not a secret, so even the broker (whose address
  space holds the cookie jar) produces a leak-free report. This is the secret
  scrubbing; it complements `RLIMIT_CORE = 0` (which would otherwise spill those
  pages to disk). A production minidump would add a register set and a
  frame-pointer stack walk with the stack/heap redacted — out of scope here.
- **Still dies with the signal.** The handler restores `SIG_DFL` and *returns*;
  the synchronous fault re-executes and the default action kills the process with
  the original signal (`SA_NODEFER` keeps it unmasked). It deliberately does not
  `tgkill` to re-raise — the seccomp `tgkill` rule permits only SIGSYS-to-self, so
  a re-raise would itself trap. So the engine's crash detection (§1.1) is
  unaffected: it still sees the child die with its signal.
- Verified by the `crash-report` probe: under the renderer lockdown, a wild read
  raises `SIGSEGV`, the `[crash]` record appears on stderr, and the process dies
  with `SIGSEGV`.

---

## 3. Windows

Windows confinement comes in two halves, and only one can be self-applied.
**This backend is deliberately half a sandbox** and is worth reading as such.

### 3.1 Applied

| Measure | Detail | Where |
|---|---|---|
| `ProcessDynamicCodePolicy` → `ProhibitDynamicCode` | The **W^X analogue**: no new executable memory, and no making existing memory executable. Fatal if it fails | `sandbox/windows.rs` |
| `ProcessChildProcessPolicy` → `NoChildProcessCreation` | The analogue of `execve`/`clone` being off the allowlist. Fatal if it fails | ″ |
| `ProcessExtensionPointDisablePolicy` → `DisableExtensionPoints` | Refuses the legacy injection vectors (AppInit_DLLs, global window hooks, IME plugins). No Unix counterpart. Fatal if it fails | ″ |
| `ProcessSystemCallDisablePolicy` → `DisallowWin32kSystemCalls` | win32k lockdown — removes a large kernel attack surface. **Best-effort**: a process that has initialized the GUI subsystem cannot take it, and refusing to start there would be worse | ″ |
| **Low integrity** (`S-1-16-4096` via `SetTokenInformation`) | Mandatory access control: cannot write to any object labelled medium or above — essentially the whole user profile and registry. Self-applicable because a token may always *lower* its own level. Applied last, after the pure capability removals. Best-effort | ″ |
| **Restricted primary token** (`CreateRestrictedToken`) | `DISABLE_MAX_PRIVILEGE` (every privilege stripped but `SeChangeNotify`) + Administrators marked **deny-only** (matches DENY aces, never ALLOW). Handed to the child at `CreateProcessAsUserW`; falls back to the inherited token if the host refuses | `sandbox/windows.rs` + `spawn/windows.rs` |
| **AppContainer** (per-role lowbox, env-gated `GOSUB_WIN_APPCONTAINER`) | The parent-side, object-confining half. Each role runs under its own registered lowbox profile (`CreateAppContainerProfile`) attached at `CreateProcess` via `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`: the **net** component gets the `internetClient` capability and renderers get **none** (no network) — the renderer/net split the other backends enforce. Each filesystem **service** is granted access to only its own path (ALL APPLICATION PACKAGES / its container SID ACL, with a Low-integrity relabel so the lowbox can write). Needs the image at an app-package-accessible install location, so it is opt-in rather than default-on. Validated end-to-end on Windows 11 | `sandbox/windows.rs` + `spawn/windows.rs` |
| **Job object** (parent-side, post-spawn) | `PROCESS_MEMORY` = 512 MiB (the `RLIMIT_AS` analogue Windows otherwise lacks), `ACTIVE_PROCESS = 1` (belt and braces with the child-process policy), `KILL_ON_JOB_CLOSE` (an engine that crashes takes its renderers with it rather than orphaning them). The job handle is **intentionally leaked** — closing it is exactly what arms `KILL_ON_JOB_CLOSE` | ″ |
| `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` | Handle inheritance on Windows is process-wide, so `HANDLE_FLAG_INHERIT` exposes a handle to *every* concurrent child. The explicit list restores the property the Unix side gets from clearing `FD_CLOEXEC` inside the forked child | `spawn/windows.rs` |
| SID alignment fix | A SID must be DWORD-aligned; a bare `[u8; 68]` intermittently faulted `CreateRestrictedToken` with `ERROR_NOACCESS`, which made a broken token *sometimes* build and mimic a working sandbox | `sandbox/windows.rs` |

### 3.2 Absent / caveats on Windows

- **AppContainer is env-gated, not default-on.** A lowbox can only load images the
  filesystem grants an app-package SID, so the binary must sit at an
  app-package-accessible install location (`C:\ProgramData` / `C:\Program Files`)
  — the real installer requirement Chromium also has, which CI's `target\` dir
  does not meet. So the renderer/net network split and per-service file scoping are
  present and validated, but behind `GOSUB_WIN_APPCONTAINER` rather than always on.
- **Restricting-SID token** (the strong form, ≈ no file access) stays out for the
  same image-loading reason. Established *empirically*, not assumed: a child
  created under it dies in the loader, because image and DLL loading are
  access-checked against the **primary** token and nothing on disk grants
  `RESTRICTED` read. Chromium's two-phase drop does not rescue it — thread
  impersonation does not cover the loader's image section mapping. The AppContainer
  is what clears that wall instead.
- `deny_debugger_attach` is an honest **no-op**: a Windows process cannot refuse
  same-user debugging the way `PR_SET_DUMPABLE`/`PT_DENY_ATTACH` can. DACL
  stripping raises the bar but anyone holding `SeDebugPrivilege` bypasses it;
  the real mechanism is Protected Process Light, which needs a certificate a
  normal application will not have.
- The shared-memory tile and ring transports are Linux-only, so Windows uses the
  in-band copy path.

---

## 4. macOS

| Measure | Detail |
|---|---|
| **Seatbelt** (`sandbox_init`) SBPL profile, starting from `(deny default)` | The mechanism backing App Sandbox and Chromium's macOS renderer sandbox. Gates *operations*, so file/network/exec confinement all live in one profile rather than a syscall list |
| Renderer profile | `(deny default)` + `signal (target self)` + `process-info* (target self)`. Nothing else — no `mach-lookup`, no `sysctl-read`, no files, no network. Each grant is a privilege a compromised renderer could turn against the host, so the list is kept minimal |
| Net profile | The renderer profile + `network-outbound` + `system-socket` — the one role that keeps the network |
| Service profile | `(deny default)` + **path-scoped** file access for filesystem services — `file-read*` (and, where writable, `file-write*`) on *only* the service's own declared path via `(subpath …)`/`(literal …)`, plus a broad `file-read-metadata` so path lookup resolves (the SBPL counterpart of the Linux services' Landlock ruleset). Device services instead get the broad `file-read*`/`file-write*` + `iokit-open` (the `ioctl`/device-node analogue). Validated on an M1 |
| **Mach bootstrap denied** | `(deny default)` withholds `mach-lookup`, so a renderer cannot reach the bootstrap namespace (WindowServer, launchd services, privileged daemons) — the classic macOS escape surface, and *tighter* than Chromium's allow-specific-global-names approach (this stub renderer needs none). Verified by the `seatbelt-mach-lookup` probe. Residual: the window between `exec` and lockdown, where the inherited bootstrap port is still live but only the PoC's own handshake code runs — a production build would replace the bootstrap port with a restricted namespace to close it |
| Fail-closed | If `sandbox_init` refuses the profile the component aborts, exactly as on Linux |
| `ptrace(PT_DENY_ATTACH)` | The `PR_SET_DUMPABLE` analogue: refuses future `PT_ATTACH`/`task_for_pid` |
| rlimits | `RLIMIT_NOFILE` = 128, `RLIMIT_CORE` = 0, nice +10 |

Seams that do **not** line up with Linux, by design:

- **Network isolation folds into the profile.** No namespaces, so
  `isolate_network` is a no-op and the renderer's profile simply omits
  `network*`. Net effect is the same.
- **No `PROT_EXEC`/W^X argument filtering.** SBPL gates operations, not syscall
  arguments, so the fine-grained writable-xor-executable rule has no direct
  analogue. `(deny default)` still denies the file/network/exec escalation
  surface.
- **No per-process memory cap** a third-party app can self-impose (unlike the
  Linux cgroup `memory.max` / Windows job cap). `RLIMIT_AS` is rejected outright
  (`EINVAL`); `RLIMIT_DATA` is accepted but ineffective (macOS allocators use
  `mmap`, which it does not count); the kernel ledger limits
  (`task_set_phys_footprint_limit` / `memorystatus`, what Jetsam enforces) are
  gated behind root or the Apple-*private* `com.apple.private.memorystatus`
  entitlement — verified on an M1: `task_set_phys_footprint_limit(mach_task_self,
  …)` returns `KERN_NO_ACCESS` unprivileged. So a macOS content process is bounded
  by the **OS's Jetsam** under memory pressure, exactly as Chromium's is.
- **`sandbox_init` is deprecated API** (since 10.7) yet remains what every
  shipping browser uses; production would move to the App Sandbox entitlement
  model.
- The `PT_DENY_ATTACH` probe checks only that the kernel *accepted* the request,
  not that an attach is subsequently refused — an unprivileged macOS process
  cannot `PT_ATTACH` even to its own child without SIP disabled, so the control
  case proves nothing either way.
- The shared-memory tile and ring transports are Linux-only.

---

## 5. Other Unixes (BSD, illumos, …)

`sandbox/unsupported.rs` — multi-process mode builds and runs (socketpairs,
inherited-fd auth and `SCM_RIGHTS` all carry over), but **every privilege drop
is an honest no-op** and the components say so at startup. The architecture is
exercised; the confinement is not. Deliberately all-or-nothing rather than a
partial illusion of confinement — wiring up `pledge`/`unveil` or Capsicum would
be a backend-shaped piece of work.

---

## 6. How the measures are verified

- **Probe suite** (`selftest.rs`), asserted against a per-platform expectation
  so a probe that silently disappears behind a `cfg` fails the build:
  - **Linux (22)**: `baseline`, `mprotect-exec`, `socket`, `memfd-seal`,
    `fcntl-dupfd`, `ring`, `netns`, `pidns`, `no-ptrace`, `forkserver-can-fork`,
    `forkserver-canary-gap`, `forkserver-no-exec`, `forkserver-no-socket`,
    `forkserver-no-newuser-clone`, `service-fs-openat`, `service-fs-no-socket`,
    `service-device-ioctl`, `service-landlock`, `broker-landlock`,
    `broker-seccomp`, `cgroup-memory-limit`, `crash-report`.
  - **macOS (13)**: `seatbelt-file`, `seatbelt-network`, `seatbelt-exec`,
    `seatbelt-net-role-keeps-network`, `seatbelt-baseline`,
    `seatbelt-file-write`, `seatbelt-fork`, `seatbelt-signal-other`,
    `seatbelt-sysctl`, `seatbelt-mach-lookup`, `seatbelt-service-scope`,
    `rlimits`, `ptrace-deny-accepted`.
  - **Windows (7)**: `mitigation-baseline`, `mitigation-dynamic-code`,
    `mitigation-child-process`, `mitigation-policies-readback`,
    `low-integrity`, `job-memory-limit`, `restricted-token`.
- **Unit tests**: SSRF classifier (internal ranges, alternate encodings, IPv6,
  userinfo/trailing-dot), cookie broker (`(zone, origin)` partitioning +
  HttpOnly hiding), IPC framing and oversized-length rejection, the per-source
  `Gate`, origin parsing, decoder rejections, storage path-traversal, and the
  consumer-side shm/ring refusals (unsealed fds, undersized fds, absurd
  dimensions/lengths, corrupt cursors, aborted and truncated streams).
- **Integration tests** run the actual built binary in both modes and confirm
  the children both *announce* and *enforce* their sandbox.
- **Checked by hand** (needs external tooling): the fork server forking
  renderers *without* exec (an `execve` strace shows only
  `fork-server`/`net-daemon`), and the per-source inbox bound holding engine RSS
  flat under a message flood (~2.8 MB steady vs ~90 MB/s growth without it).

---

## 7. Known gaps

Listed so no guarantee above is over-read.

**The sharpest edge.** The engine (broker) *is* now loosely confined — a Landlock
write-jail and a seccomp **deny-list** that removes the escalation primitives
(§2.1, §2.3), the posture Chromium's browser process takes. What remains is that
the parser is not **isolated**: every frame a renderer or the net component sends
is `bincode::deserialize`d *inside* the process holding every secret, with full
ambient authority over that memory — the deny-list removes kernel-escalation
reach, not the parser's reach into those secrets. What bounds it today is the
16 MiB length-checked framing, closed enums, bincode's lack of type-directed
dispatch, and a `cargo-fuzz` harness over the parsers — a narrow surface, not an
open one. The remaining step a production engine would take is to run the parser
in a *minimized subprocess* rather than the secret-holding one.

Others:

- **SSRF cannot resolve hostnames** offline; a real one resolves DNS, re-checks
  the resolved IPs, and **pins** that IP for the connection to defeat DNS
  rebinding.
- **Egress destinations are not constrained by seccomp** — `connect` takes a
  pointer seccomp cannot dereference — so a real deployment adds a netns +
  firewall rules rather than trusting the in-process check alone.
- **Remaining namespaces**: net/IPC/UTS and a shared renderer **PID** namespace
  are applied (§2.4); an empty-root **mount** namespace (`pivot_root`) and
  *per-renderer* PID namespaces are not — both blocked by the same
  `uid_map`-less-userns constraint (a `uid_map` write is refused by AppArmor + the
  broker Landlock). A per-arch seccomp baseline tested across libc/kernel versions
  is also still wanted (the startup canary verifies the libc-sensitive filter, but
  CI does not yet exercise every target).
- **cgroup refinements — considered, not pursued.** Three polish items on the
  cgroup memory bound (§2.5) were each found not worth it:
  - A **cgroup namespace** (`CLONE_NEWCGROUP`) would only hide the host cgroup
    layout in `/proc/self/cgroup` — which a renderer cannot read anyway (`openat`
    is off its allowlist) — and its namespace root, fixed at `unshare` time in
    `pre_exec`, would be stale against the *post-spawn* cgroup placement. No gain,
    a cosmetic wart.
  - **`oom_score_adj`** (biasing the global OOM killer toward renderers) is a write
    to `/proc/<pid>/oom_score_adj`; the **broker Landlock** confines writes to the
    temp dir + the cgroup subtree, so it is denied — for the child (which inherits
    that Landlock in `pre_exec`) and for the broker alike. Widening Landlock to
    `/proc` to allow it would be a real regression for what is only a *hint* the
    cgroup `memory.max` already subsumes where it is available.
  - **Race-free `clone3(CLONE_INTO_CGROUP)`** placement does not fit: `Command`
    cannot pass clone flags (services), and the fork server's `clone3`→`ENOSYS`
    hardening plus fork-without-exec make atomic-into-cgroup incompatible. The
    current post-spawn placement's race is microseconds — a child cannot balloon
    its memory before it is moved into its bounded cgroup.
- **A real JS JIT needs executable memory**, so it would carve out a dedicated
  JIT exception rather than deny `PROT_EXEC` outright (same on Windows for
  `ProhibitDynamicCode`).
- **GPU and audio are intentional stubs** (a PoC *scope boundary*, not a
  shortcut) — real processes with the correct device filter (`openat` + `ioctl`)
  and empty net/IPC/UTS namespaces, proving GPU/audio can run *out of process and
  confined*, which is the security point. The actual graphics work (compositing:
  buffer pools, damage rects, swapchain — the WebGL/canvas attack surface) is not
  a security demonstration and is deliberately out of scope. The one honest caveat
  that remains is inherent to real GPU work, not a gap the PoC needs to close:
  `ioctl` is a large, driver-defined surface seccomp constrains poorly, so the
  isolation shown is the process boundary, not a tight filter.
- **No per-process memory cap on macOS** (a platform gap, not a shortcut): no
  hard cap a third-party app can self-impose exists — `RLIMIT_AS` rejected,
  `RLIMIT_DATA` ineffective, the kernel ledger limits root/Apple-private-entitlement
  gated (`KERN_NO_ACCESS`); a macOS content process is bounded by the OS's Jetsam
  under pressure instead (§4). Linux gets a cgroup `memory.max`, Windows a job cap.
- **Blocking replies**: the loop's replies to components are blocking socket
  writes, so a renderer that floods requests *and* refuses to read replies can
  stall the loop. Memory stays bounded (the gates handle that); responsiveness
  does not.
- **`FrameReady` rides an unbounded channel** to the embedding application — a
  tile's gate permit is returned when the loop *forwards* it, not when the app
  drops it, so an app that stops draining accumulates tiles (16 MiB each).
- **Single-process mode**: the policy checks still run but a compromised
  renderer *thread* shares the engine's address space — the checks only become a
  real boundary with a process behind them.
- **Site-isolation breadth**: the cross-origin renderer *swap* is implemented
  (§1.1), but only for a single-frame tab — out-of-process iframes,
  `document.domain` agent clusters, BrowsingInstances, and the back-forward cache
  are absent. And `origin_of` is not a real URL parser (no IDNA, no userinfo;
  `host_of` in the SSRF filter remains the deliberately-hostile one — a real
  engine shares one implementation).
