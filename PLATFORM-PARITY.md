# Platform parity — where macOS and Windows lag Linux, and why

Linux is the reference implementation. macOS and Windows satisfy the *same*
public sandbox surface (`crate::sandbox`) with platform-appropriate mechanisms,
but they are not at parity. This document records the gaps honestly and sorts
each one into **portable lag** (Linux does something the others *could* do but
don't yet), **parity via a different mechanism** (comparable protection, nothing
to close), or **platform limit** (the other OS genuinely cannot match it).

For *how* each backend confines a process, see `src/sandbox/{linux,macos,windows}.rs`
and the "Platform status" note in `README.md`. This doc is only about the deltas.

## At a glance

| Property                              | Linux                              | macOS                            | Windows                                   |
| ------------------------------------- | ---------------------------------- | -------------------------------- | ----------------------------------------- |
| Syscall / capability confinement      | seccomp allow-list (per-syscall)   | Seatbelt `(deny default)`        | mitigation policies + AppContainer        |
| No new programs (`execve`)            | off the allow-list → SIGSYS        | `(deny process-exec*)`           | `PROCESS_CREATION_MITIGATION … CHILD…`    |
| W^X (no writable+executable memory)   | `mprotect(PROT_EXEC)` → SIGSYS     | Seatbelt (no JIT entitlement)    | ACG (dynamic-code prohibited)             |
| Filesystem scoping                    | Landlock + zero opens in renderer  | Seatbelt subpath grants          | AppContainer per-role path (env-gated)    |
| Renderer has no network               | empty net namespace                | `(deny network*)`                | AppContainer w/o `internetClient`         |
| Per-process **memory cap**            | cgroup v2 `memory.max`             | **none** (Jetsam only)           | job-object memory cap                     |
| Inbound debugger denial               | `PR_SET_DUMPABLE(0)`               | `ptrace(PT_DENY_ATTACH)`         | `deny_debugger_attach` (best-effort)      |
| Fork-server / zygote (no re-exec)     | **yes** (fork + namespaces)        | no — `fork+exec`                 | no — `CreateProcess`                      |
| Zero-copy tile / body transport       | **yes** (sealed `memfd`)           | no — in-band socket copy         | no — in-band pipe copy                    |
| Out-of-process **cookie vault**       | **yes** (net-direct)               | no — jar in the broker           | no — jar in the broker                    |
| DoS timeouts (reply-write, decode)    | enforced                           | enforced                         | enforced (`CancelIoEx` watchdog)          |
| Self-captured scrubbed crash report   | **yes**                            | no                               | no                                        |
| Sandbox probes that assert this       | 23                                 | 13                               | 4 + AppContainer end-to-end               |

## A. Portable lag — Linux-only, but the others *could* do it

These are not platform limits; they are simply not ported yet. Import-relevant.

1. **The cookie vault.** On Linux (multi-process) the cookie jar lives in a
   separate low-authority `vault` process, net is its sole client, and HttpOnly
   never touches the broker. macOS and Windows still keep the jar **in the
   broker**. macOS can close this with essentially the Linux design — it has
   `SCM_RIGHTS` fd-passing over its unix sockets, so the net↔vault bind works the
   same way. Windows needs the handle-passing equivalent (duplicate the socket/
   pipe handle into the child at spawn), so it is more work but not blocked.

2. **The two DoS-mitigation timeouts on Windows — now closed.** The reply-write
   deadlock guard and the decoder stall timeout are `set_write_timeout` /
   `set_read_timeout`, real on unix but with no `std` equivalent for a Windows
   anonymous pipe (it was a no-op there). Rather than convert to overlapped I/O —
   which would force a *named* pipe and reintroduce the rendezvous race the
   anonymous-pipe design deliberately avoids — the Windows channel now enforces
   the deadline with a watchdog thread that calls `CancelIoEx` on the pipe handle
   once it passes (the supported way to abort a *synchronous* `ReadFile`/
   `WriteFile` issued by another thread). The aborted call surfaces as
   `io::ErrorKind::TimedOut`, the exact kind both callers already match on, so the
   reply-write and decode-stall bounds now hold on **all three** platforms.
   Windows-gated tests in `channel/windows.rs` exercise both directions.

3. **Self-captured scrubbed crash reports.** Linux installs a `SIGSEGV`/`SIGSYS`
   handler on an alternate stack that writes a scrubbed report. macOS and Windows
   rely on the OS crash reporter and do not produce the same self-captured,
   secret-scrubbed artifact.

4. **Zero-copy transports.** Rendered tiles and streamed bodies cross the process
   boundary via a sealed `memfd` on Linux (fd passed, pages mapped read-only);
   macOS and Windows fall back to copying the bytes in-band. macOS *could* get an
   equivalent with `shm_open`/Mach memory and Windows with a shared section — both
   are real work, and the copy path is correct and safe, just not zero-copy.

## B. Parity via a different mechanism — comparable, nothing to close

Different kernel, different primitive, comparable result. These are **not** gaps.

- **Syscall vs. capability confinement.** Linux filters individual syscalls
  (seccomp allow-list, default-deny → SIGSYS). Windows has no syscall filter;
  instead **process mitigation policies** remove whole *capability classes*
  (dynamic code / ACG = W^X, child-process creation, DLL injection, win32k) and an
  **AppContainer** confines the *objects* a process may touch (files, registry,
  network, other processes). macOS uses **Seatbelt** (`sandbox_init`, `(deny
  default)`) which denies by operation. The granularity differs; the renderer/net
  split and "no new programs / no executable memory / no network" properties hold
  on all three.

- **Filesystem scoping.** Landlock (Linux) ≈ Seatbelt `subpath` grants (macOS) ≈
  AppContainer per-role path (Windows, env-gated behind `GOSUB_WIN_APPCONTAINER`
  because a lowbox can only load images from an app-package-accessible install
  location). Each confines a file service to its own directory.

- **Inbound debugger denial.** `PR_SET_DUMPABLE(0)` (Linux) ≈ `PT_DENY_ATTACH`
  (macOS). On Windows it is best-effort (`deny_debugger_attach`).

- **Memory cap on Windows** is a job-object limit rather than a cgroup, but it is a
  real per-process resident cap — parity with Linux here (macOS is the outlier;
  see C).

## C. Platform limits — the other OS genuinely cannot match Linux

These are not "not done"; they are blocked by the platform.

1. **macOS has no per-process memory cap available to a third party.** Linux
   bounds a child's resident memory with cgroup `memory.max` and Windows with a
   job-object cap. On macOS the real memory-ledger limits
   (`task_set_phys_footprint_limit`, `memorystatus_control`) are gated behind
   root or the Apple-private `com.apple.private.memorystatus` entitlement
   (verified returning `KERN_PROTECTION_FAILURE` / `EPERM` on an M1). A macOS
   content process is bounded only by the OS's **Jetsam** (priority-based reclaim
   under pressure), not a hard cap. Documented at length in `src/sandbox/macos.rs`.

2. **The fork-server / zygote model is Linux-specific.** Forking content
   processes from a warm, pre-initialized image *without* re-exec — each landing
   in its own PID namespace — relies on `fork` + Linux namespaces. macOS and
   Windows create fresh processes (`fork+exec` / `CreateProcess`), so they pay
   full process-init cost per child and cannot offer the "never execs a new
   program image" property structurally (they rely on the mitigation/Seatbelt
   `exec` denial to get the *security* half back — see A/B).

3. **Per-syscall granularity** itself. Even a fully-locked-down Windows/macOS
   process is confined by *capability class* or *operation*, not by an
   allow-list of individual syscalls. A novel syscall a Linux seccomp allow-list
   has never heard of is denied by default (fail-closed); the capability-class
   model can only deny classes it enumerates. This is a genuine expressiveness
   difference, not an implementation gap.

## Verification

Each row above is asserted by probes that *attempt* the forbidden thing and check
the platform kills or refuses it: **Linux 23**, **macOS 13**, **Windows 4** plus
end-to-end AppContainer validation on Windows 11. Run `cargo test` (the
integration suite drives them) or `./target/release/gosub-proc-iso-poc selftest
<probe>` for one. The probe names per platform are in `src/selftest.rs` (`PROBES`).

The honest summary: **Linux is ahead on the cookie vault, the crash reporter, and
the zero-copy transports (all portable); macOS lacks a hard memory cap (a genuine
platform limit).** The one Windows-only gap — the pipe timeouts — is now closed
with a `CancelIoEx` watchdog. Everything else is parity through a
platform-appropriate mechanism.
