//! The duplex byte channel an engine↔component IPC link runs over.
//!
//! This is the transport seam, shaped like [`crate::sandbox`]: one
//! platform-neutral surface here, per-OS backends underneath, and the only
//! place a transport `target_os` cfg lives. [`crate::ipc`] frames bincode
//! messages over whatever this provides and never names a platform type.
//!
//! * `unix.rs` — a `socketpair(2)`'d `UnixStream`, split by `try_clone`.
//! * `windows.rs` — a *pair* of anonymous pipes (`CreatePipe`), one per
//!   direction, since Windows anonymous pipes are half-duplex.
//!
//! ## Why this shape
//!
//! The security property the engine depends on is that a child's link is
//! **unforgeable**: it arrives as an already-connected, inherited kernel
//! object, so there is no rendezvous path on disk, no auth token on argv that
//! another local user could read, and no `accept()` race for an attacker to
//! win. Both backends preserve exactly that, which is why neither uses a
//! *named* pipe: naming the object would put it in a namespace someone else
//! can reach and reintroduce the race.
//!
//! What travels on argv is only the child's handle *value*, which is not a
//! secret ([`Channel::to_argv`]). The two platforms disagree on how many
//! values that is — one fd on Unix, two handles on Windows — so the encoding
//! is opaque to callers and parsed only by [`Channel::from_argv`]. Role
//! argument *arity* is therefore identical everywhere: `net-daemon <link>`,
//! `renderer <origin> <link>`.
//!
//! ## Inheritance is inverted between the platforms
//!
//! Unix fds are inherited across `exec` by default and must be opted *out* of
//! with `FD_CLOEXEC`; Windows handles are not inherited by default and must be
//! opted *in* with `HANDLE_FLAG_INHERIT`. [`Channel::make_inheritable`] is the
//! common operation, but **when** it may be called differs, and the difference
//! is load-bearing:
//!
//! * Unix: from `pre_exec`, i.e. after `fork`, in the child. Clearing
//!   `FD_CLOEXEC` in the parent would expose that fd to every *other*
//!   concurrent spawn as well.
//! * Windows: in the parent, before `CreateProcess` — there is no `pre_exec`
//!   hook, so it cannot be deferred.
//!
//! The Windows ordering would leave an inheritable handle briefly visible to
//! any concurrently created child, since the flag is process-wide. That is why
//! [`crate::spawn`] names these handles in a
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`: the flag makes inheritance *possible*,
//! the list makes it *per-child*. Without the list the arrangement would be
//! safe only by accident of the engine being single-threaded.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Channel, Rx, Tx};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{Channel, Rx, Tx};
