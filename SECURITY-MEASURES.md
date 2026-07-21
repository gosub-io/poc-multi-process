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
| engine (broker) | everything — spawns, sockets, cookie jar | — | none (only `deny_debugger_attach`) |
| fork server (zygote, Linux) | `fork`/`wait4`, `prctl`/`seccomp` for children | engine | seccomp superset of content baseline, empty netns, non-dumpable |
| renderer (per `(zone, origin)`) | none | fork server | content baseline |
| decoder (ephemeral, per image) | none | fork server | content baseline (renderer lockdown reused) |
| net component | sockets (outbound only) | engine | baseline + socket family; **keeps** host netns |
| storage service | `openat` | engine | baseline + `openat` + Landlock (storage dir, rw) |
| font service | `openat` | engine | baseline + `openat` + Landlock (one file, ro) |
| audio / gpu services (stubs) | `openat` + `ioctl` | engine | baseline + device syscalls, empty netns |

The governing rule: **the zygote may only parent processes strictly less
privileged than itself.** Its filter, empty netns and non-dumpable flag are
inherited and only ever narrow — so any role needing a capability the zygote
gave up (files, devices, network) is spawned fork+exec from the engine instead,
with its own wider filter.

---

## 1. General (all platforms)

### 1.1 Process & privilege architecture

| Measure | Where | Status |
|---|---|---|
| Capability split across processes — network, filesystem, devices and rendering each live in a different process | `engine.rs`, `sandbox/mod.rs` | Applied |
| **Site isolation**: one renderer per `(zone, origin)`; the same origin in two zones is two processes with independent partitions | `engine.rs` | Applied |
| **Ephemeral image decoder** — one process decodes exactly one image and exits, so a decoder can never see a second origin's data | `decoder.rs` (`serve_one`) | Applied |
| Renderers hold **no secrets** — no cookies, no network handle; they can only send IPC messages | `renderer.rs` | Applied |
| Cross-origin navigation is refused (rather than swapping renderers) | `engine.rs` | Partial |
| Crash containment — a dead renderer surfaces as `TabCrashed` for that tab only; engine and other tabs continue | `engine.rs` | Applied |
| Fork server is **minimal, single-threaded and secret-free**, and is started *before* the engine loads any cookies | `fork_server.rs` | Applied |

### 1.2 Broker policy (the engine event loop *is* the boundary)

| Measure | Detail | Status |
|---|---|---|
| **Ambient identity** — `(zone, origin)` comes from the engine's own `Tab` record; identity fields inside messages are never trusted | `tab_request` | Applied |
| Same-origin **fetch** check | `may_fetch(tab.origin, url)`; refusal prevents a renderer naming an attacker URL and having the engine attach *this* origin's cookies to it | Applied |
| Same-origin **cookie** check | `NeedCookies` compared against `tab.origin`, not the message | Applied |
| **HttpOnly cookies never reach a renderer** | `attachable_cookies` (all, → net) vs `visible_cookies` (non-HttpOnly, → renderer). The session token travels engine → net and skips the renderer's address space | Applied |
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

Knowingly not classified: subnet-directed broadcast (`x.y.z.255`) — it depends
on the local netmask. Hostname resolution and DNS-rebinding pinning are
**Absent** (see §7).

### 1.4 IPC hardening

| Measure | Detail | Status |
|---|---|---|
| **Inherited descriptor is the authentication** — a `socketpair(2)` (Unix) / anonymous pipe pair (Windows) passed at spawn | No rendezvous path on disk, no auth token on argv (readable via `/proc/<pid>/cmdline`), no `accept()` race, unforgeable | Applied |
| Every other engine fd stays `CLOEXEC`; the one descriptor a child should inherit is un-marked **inside the forked child** (`pre_exec`), not in the parent | so a concurrent spawn never leaks another renderer's channel | Applied |
| Length-prefixed frames with a **16 MiB** cap checked *before* allocating | `MAX_FRAME_LEN` in `ipc.rs` — a corrupt length prefix cannot force an unbounded allocation | Applied |
| Closed wire enums + bincode (no type-directed dispatch, unlike pickle / Java serialization / `serde_yaml` tags) | narrow deserialization surface | Partial |
| `SCM_RIGHTS` receive walks **all** control messages, adopts every fd the kernel installed, and enforces exactly-one | a peer stuffing extra fds gets a refusal and all fds closed, instead of leaking descriptors into the engine's fd table | Applied |
| Received fds are `MSG_CMSG_CLOEXEC` and wrapped in `OwnedFd` | no leak on an early return | Applied |
| Dynamic-loader injection vectors stripped from the child environment before `exec` (`LD_*`, `DYLD_*`) | otherwise attacker-supplied library code runs *before* the child reaches its own lockdown | Applied |

### 1.5 Resource and DoS bounds

| Bound | Value | Purpose |
|---|---|---|
| `MAX_QUEUED_PER_SOURCE` | 64 messages | Per-source inbox gate: a reader thread takes a permit before forwarding and the loop returns one after handling. Out of permits ⇒ the reader stops draining that socket ⇒ the OS backpressures the component. Because it is **per source**, one flooding renderer pins a fixed slice of engine memory (measured: engine RSS flat vs ~90 MB/s growth to OOM without it) |
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
  enumerated; everything else is a fatal `SIGSYS` (`KillProcess`, not `EPERM` —
  a killed process cannot probe the sandbox and adapt). Fail-closed: a syscall
  never considered (a new one, or an io_uring-based networking bypass) is denied
  for free.
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

### 2.2 Argument filtering

| Rule | Effect |
|---|---|
| `mmap`/`mprotect` allowed only when `PROT_EXEC` is clear (`MaskedEq(PROT_EXEC) == 0` on arg 2) | **W^X** — a renderer can never turn writable memory executable, the step most memory-corruption chains need to run injected code. `mremap` preserves an existing mapping's protection, so it cannot introduce exec |
| `fcntl` allowed only for `F_ADD_SEALS`, `F_GET_SEALS`, `F_GETFD` | every *mutating* command — `F_DUPFD` (fd fabrication), `F_SETFL`, locks — is a fatal `SIGSYS` |
| Fork server only: additionally `F_DUPFD_CLOEXEC`, and `F_SETFD` **only with `FD_CLOEXEC`** | permits *setting* close-on-exec but never clearing it (which would leak a descriptor across an exec) |

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

### 2.4 Network namespace

- Renderers (via the fork server) and every service except the net component run
  in an **empty network namespace** — no interfaces at all, so there is nothing
  to connect to even if a syscall slips through the filter. The two layers fail
  independently.
- Obtained unprivileged via `CLONE_NEWUSER | CLONE_NEWNET` (a bare
  `CLONE_NEWNET` needs `CAP_SYS_ADMIN`), from `pre_exec`, fail-closed.
- `/proc/self/uid_map` is deliberately **left unwritten**, so the child runs as
  the overflow uid (`nobody`) — strictly better than an identity map, and it
  survives distros that block the map write (Ubuntu 24.04+
  `kernel.apparmor_restrict_unprivileged_userns=1`).

### 2.5 Resource ceilings (`pre_exec`, async-signal-safe)

| Limit | Value | Rationale |
|---|---|---|
| `RLIMIT_AS` | 512 MiB | An over-allocating child aborts *that process*, not the machine |
| `RLIMIT_NOFILE` | 128 | A child needs its IPC socket + std streams |
| `RLIMIT_CORE` | 0 | A crash must not dump a core full of cookies/tokens |
| `setpriority` | nice +10 | A compromised child spinning in a loop cannot starve the trusted engine/UI. (A hard `RLIMIT_CPU` is unusable — it counts *cumulative* time and would kill a legitimately long-lived renderer) |

rlimits only ever lower, and raising the nice value needs no privilege, so a
child cannot undo either.

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
| **Job object** (parent-side, post-spawn) | `PROCESS_MEMORY` = 512 MiB (the `RLIMIT_AS` analogue Windows otherwise lacks), `ACTIVE_PROCESS = 1` (belt and braces with the child-process policy), `KILL_ON_JOB_CLOSE` (an engine that crashes takes its renderers with it rather than orphaning them). The job handle is **intentionally leaked** — closing it is exactly what arms `KILL_ON_JOB_CLOSE` | ″ |
| `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` | Handle inheritance on Windows is process-wide, so `HANDLE_FLAG_INHERIT` exposes a handle to *every* concurrent child. The explicit list restores the property the Unix side gets from clearing `FD_CLOEXEC` inside the forked child | `spawn/windows.rs` |
| SID alignment fix | A SID must be DWORD-aligned; a bare `[u8; 68]` intermittently faulted `CreateRestrictedToken` with `ERROR_NOACCESS`, which made a broken token *sometimes* build and mimic a working sandbox | `sandbox/windows.rs` |

### 3.2 Absent on Windows (the other half)

- **Restricting-SID token** (the strong form, ≈ no file access). Established
  *empirically*, not assumed: a child created under it dies in the loader,
  because image and DLL loading are access-checked against the **primary**
  token and nothing on disk grants `RESTRICTED` read. Chromium's two-phase drop
  does not rescue it — thread impersonation does not cover the loader's image
  section mapping. Making it usable requires ACLing the executable and every DLL
  for the `RESTRICTED` SID at install time (an installer concern).
- **AppContainer** — which is what would give the renderer/net network split.
- Consequently: **no network isolation and no file-access confinement**, and
  the per-role distinction the other backends enforce (renderers have no
  network, the net component does) **does not exist here** — every role gets
  the same policy set.
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
| Service profile | `(deny default)` + `file-read*`/`file-write*` for filesystem services, plus `iokit-open` for device services (the closest analogue to `ioctl` on a device node) |
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
- **No `RLIMIT_AS`.** macOS rejects the call outright (`EINVAL`) rather than
  accepting-but-not-enforcing, so the address-space cap is simply unavailable.
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
  - **Linux (16)**: `baseline`, `mprotect-exec`, `socket`, `memfd-seal`,
    `fcntl-dupfd`, `ring`, `netns`, `no-ptrace`, `forkserver-can-fork`,
    `forkserver-canary-gap`, `forkserver-no-exec`, `forkserver-no-socket`,
    `service-fs-openat`, `service-fs-no-socket`, `service-device-ioctl`,
    `service-landlock`.
  - **macOS (11)**: `seatbelt-file`, `seatbelt-network`, `seatbelt-exec`,
    `seatbelt-net-role-keeps-network`, `seatbelt-baseline`,
    `seatbelt-file-write`, `seatbelt-fork`, `seatbelt-signal-other`,
    `seatbelt-sysctl`, `rlimits`, `ptrace-deny-accepted`.
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

**The sharpest edge.** The engine (broker) is **unsandboxed** — the privileges a
filter would drop are exactly the ones it exists to exercise. But it is not
unsandboxed because it is safe from hostile input: every frame a renderer or the
net component sends is `bincode::deserialize`d inside the process holding every
secret, with full ambient authority and no filter behind it. What bounds it
today is the 16 MiB length-checked framing, closed enums, and bincode's lack of
type-directed dispatch — a narrow surface, not an open one. A production engine
would confine the broker too (Chromium sandboxes its browser process, just far
more loosely) and keep the parser minimal and fuzzed.

Others:

- **SSRF cannot resolve hostnames** offline; a real one resolves DNS, re-checks
  the resolved IPs, and **pins** that IP for the connection to defeat DNS
  rebinding.
- **Egress destinations are not constrained by seccomp** — `connect` takes a
  pointer seccomp cannot dereference — so a real deployment adds a netns +
  firewall rules rather than trusting the in-process check alone.
- **Remaining namespaces** (mount / PID / IPC) and `pivot_root` are not applied;
  neither is a per-arch seccomp baseline tested across libc/kernel versions.
- **A real JS JIT needs executable memory**, so it would carve out a dedicated
  JIT exception rather than deny `PROT_EXEC` outright (same on Windows for
  `ProhibitDynamicCode`).
- **Audio and GPU are honest stubs** — real processes with the correct filter
  and empty netns, but no real work. `ioctl` is a large, driver-defined surface
  seccomp constrains poorly, so the isolation they demonstrate is the process
  boundary, not a tight filter.
- **The fork server is unsandboxed on its own terms** (minimal, trusted,
  secret-free) apart from its inherited filter; a real one would confine itself
  around the `fork()`/fd-passing path.
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
- **Cross-origin navigation is refused** rather than swapping renderers, and
  `origin_of` is not a real URL parser (no IDNA, no userinfo; `host_of` in the
  SSRF filter remains the deliberately-hostile one — a real engine shares one
  implementation).
- **Phase 3 (GPU process)** is not modeled; structurally it is the same pattern
  as the net component.
