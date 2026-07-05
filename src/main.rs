//! Proof of concept for gosub-engine issue #1080:
//! "Process Isolation for Security: Multi-Process Architecture".
//!
//! The engine runs in one of two setups over the *same* component code and
//! broker protocol; only the transport and spawning differ:
//!
//! ```text
//! multi-process (default)             single-process
//! engine (parent, broker)             engine (broker)
//! ├── net-daemon        [process]     ├── net component     [thread]
//! ├── renderer example.com  [""]      ├── renderer example.com  [""]
//! └── renderer attacker.com [""]      └── renderer attacker.com [""]
//! ```
//!
//! Selection is two-level:
//! - compile time: the `multi-process` cargo feature (on by default) gates
//!   all process/socket code; `--no-default-features` builds a
//!   single-process-only engine (e.g. for platforms without fork/UDS).
//! - run time: when the feature is compiled in, `--single-process` still
//!   selects the thread-based setup (like Chromium's `--single-process`).
//!
//! IPC is bincode frames either way: over Unix domain sockets
//! (multi-process) or in-process channels (single-process).

mod ipc;
mod net_daemon;
mod parent;
mod renderer;

use parent::Mode;

#[cfg(feature = "multi-process")]
const DEFAULT_MODE: Mode = Mode::Multi;
#[cfg(not(feature = "multi-process"))]
const DEFAULT_MODE: Mode = Mode::Single;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => parent::run(DEFAULT_MODE),
        Some("--single-process") => parent::run(Mode::Single),
        Some("--multi-process") => {
            #[cfg(feature = "multi-process")]
            parent::run(Mode::Multi);
            #[cfg(not(feature = "multi-process"))]
            {
                eprintln!("this binary was built without the `multi-process` feature");
                std::process::exit(2);
            }
        }
        // Internal child roles, used by the engine to re-exec itself.
        #[cfg(feature = "multi-process")]
        Some("net-daemon") => net_daemon::run(&args[2], &args[3]),
        #[cfg(feature = "multi-process")]
        Some("renderer") => renderer::run(&args[3], &args[2], &args[4]),
        Some(other) => {
            eprintln!("unknown argument: {other}");
            eprintln!("usage: gosub-proc-iso-poc [--single-process | --multi-process]");
            std::process::exit(2);
        }
    }
}
