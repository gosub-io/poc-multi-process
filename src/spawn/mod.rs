//! Spawning a child component — the third platform seam, alongside
//! [`crate::channel`] (how children talk) and [`crate::sandbox`] (how children
//! are confined).
//!
//! ## Why this exists rather than `std::process::Command`
//!
//! `Command` is sufficient on Unix, where a child confines *itself* after
//! `exec` and the parent's only job is to hand over a descriptor. Windows is
//! not like that: its access controls — a restricted token, an AppContainer —
//! must be supplied to `CreateProcess` *at the moment the process is created*,
//! and `Command` exposes no way to pass either a token or a
//! `PROC_THREAD_ATTRIBUTE_LIST`. Confining a Windows child therefore requires
//! owning the spawn call.
//!
//! So this module provides one [`Child`] type and one [`spawn`] entry point,
//! implemented over `Command` on Unix and `CreateProcessW` on Windows.
//!
//! ## What the Windows path buys immediately
//!
//! Even before any token work, owning the spawn closes a real gap. Handle
//! inheritance on Windows is process-wide: marking a handle inheritable makes
//! it visible to *every* concurrently created child, not just the intended one
//! (see the note in `channel/mod.rs`). `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
//! replaces that with an explicit per-spawn allowlist — this child receives
//! exactly these handles and nothing else — which restores the property the
//! Unix side gets for free by setting `FD_CLOEXEC` in the forked child.
//!
//! It also removes the single-threaded-spawner caveat that made the old
//! approach safe only by accident of the engine's structure.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{spawn, Child};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{spawn, Child};
