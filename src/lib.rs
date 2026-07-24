//! Proof of concept for gosub-engine issue #1080:
//! "Process Isolation for Security: Multi-Process Architecture".
//!
//! The engine is event-driven, shaped like the real gosub engine: commands
//! in through an `EngineHandle`, events out through a channel. Underneath,
//! its components run in one of two setups over the *same* code and broker
//! protocol; only the transport and spawning differ:
//!
//! ```text
//! multi-process (default)             single-process
//! engine event loop (broker)          engine event loop (broker)
//! ├── net component     [process]     ├── net component     [thread]
//! ├── renderer origin A     [""]      ├── renderer origin A     [""]
//! └── renderer origin B     [""]      └── renderer origin B     [""]
//! ```
//!
//! Selection is two-level:
//! - compile time: the `multi-process` cargo feature (on by default) gates
//!   all process/socket code; `--no-default-features` builds a
//!   single-process-only engine (e.g. for platforms without fork/UDS).
//! - run time: when the feature is compiled in, `--single-process` still
//!   selects the thread-based setup (like Chromium's `--single-process`).
//!
//! This is the library crate: everything the binary (`src/main.rs`) and the
//! fuzz targets (`fuzz/`) build on. The modules are `pub` so untrusted-input
//! parsers — `decoder::decode`, `ipc::recv_msg`, `ip_utils::resolve_and_pin` —
//! can be exercised directly by fuzzers and tests.

// The transport seam, mirroring `sandbox`: the only place a `target_os` cfg
// for the IPC byte channel lives. Multi-process only — single-process links
// are in-process channels.
#[cfg(feature = "multi-process")]
pub mod channel;
pub mod decoder;
pub mod device_service;
pub mod engine;
pub mod events;
pub mod font;
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub mod fork_server;
pub mod ip_utils;
pub mod ipc;
pub mod net_daemon;
pub mod orb;
pub mod renderer;
pub mod storage;
// The vault (cookie store) is Linux-only, like the fork server / shm / ring it
// shares fd-passing machinery with.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub mod vault;
// Unconditional: the per-OS confinement machinery inside is feature-gated, but
// `deny_debugger_attach` applies to the single-process build too — that build
// still holds the cookie jar in its address space. The platform backend
// (seccomp / Seatbelt / none) is selected inside the module.
pub mod sandbox;
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub mod ring;
// Compiled on every platform (not just Linux) so the integration suite can
// query the probe inventory anywhere — a platform with no probes must fail
// loudly rather than silently skip its enforcement tests.
#[cfg(feature = "multi-process")]
pub mod selftest;
// The spawn seam: how a child process is created. Owned rather than delegated
// to std::process::Command because Windows access controls must be supplied at
// CreateProcess time.
#[cfg(feature = "multi-process")]
pub mod spawn;
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub mod shm;
