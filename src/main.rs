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

mod engine;
mod events;
mod ipc;
mod net_daemon;
mod renderer;
#[cfg(feature = "multi-process")]
mod sandbox;

use engine::Mode;
use events::{EngineEvent, ZoneId};

#[cfg(feature = "multi-process")]
const DEFAULT_MODE: Mode = Mode::Multi;
#[cfg(not(feature = "multi-process"))]
const DEFAULT_MODE: Mode = Mode::Single;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => run(DEFAULT_MODE),
        Some("--single-process") => run(Mode::Single),
        Some("--multi-process") => {
            #[cfg(feature = "multi-process")]
            run(Mode::Multi);
            #[cfg(not(feature = "multi-process"))]
            {
                eprintln!("this binary was built without the `multi-process` feature");
                std::process::exit(2);
            }
        }
        // Internal child roles, used by the engine to re-exec itself. The
        // trailing argument is the inherited IPC fd number (see engine.rs).
        // net-daemon <fd> ; renderer <origin> <fd>
        #[cfg(feature = "multi-process")]
        Some("net-daemon") => net_daemon::run(&args[2]),
        #[cfg(feature = "multi-process")]
        Some("renderer") => renderer::run(&args[2], &args[3]),
        Some(other) => {
            eprintln!("unknown argument: {other}");
            eprintln!("usage: gosub-proc-iso-poc [--single-process | --multi-process]");
            std::process::exit(2);
        }
    }
}

/// Minimal event-driven usage: send commands, react to events.
fn run(mode: Mode) {
    let (engine, events) = engine::start(mode);

    // Two zones = two storage/cookie partitions (think "Work" and "Personal").
    let work = ZoneId(0);
    let personal = ZoneId(1);

    // Same origin, different zones → independent cookie jars. The session
    // token is HttpOnly (never exposed to a renderer); the theme is
    // script-visible.
    engine.set_cookie(work, "example.com", "session", "work-token", true).unwrap();
    engine.set_cookie(work, "example.com", "theme", "dark", false).unwrap();
    engine.set_cookie(personal, "example.com", "session", "personal-token", true).unwrap();

    // example.com opened in both zones runs as two separate renderer processes
    // bound to (work, example.com) and (personal, example.com).
    engine.open_tab(work, "https://example.com").unwrap();
    engine.open_tab(personal, "https://example.com").unwrap();

    let mut tabs_closed = 0;
    for event in events {
        match event {
            EngineEvent::TabOpened { tab_id, zone, origin } => {
                println!("{tab_id} [{zone}]: opened for {origin}");
                engine.navigate(tab_id, format!("https://{origin}/index.html")).unwrap();
            }
            EngineEvent::FrameReady { tab_id, tile } => {
                println!(
                    "{tab_id}: frame ready — {}x{} ({} KiB)",
                    tile.width,
                    tile.height,
                    tile.pixels.len() / 1024
                );
                engine.close_tab(tab_id).unwrap();
            }
            EngineEvent::TabClosed { tab_id } => {
                println!("{tab_id}: closed");
                tabs_closed += 1;
                if tabs_closed == 2 {
                    engine.shutdown().unwrap();
                }
            }
            EngineEvent::OpenTabFailed { url, reason } => {
                println!("could not open {url}: {reason}");
            }
            EngineEvent::NavigationFailed { tab_id, reason } => {
                println!("{tab_id}: navigation failed: {reason}");
            }
            EngineEvent::TabCrashed { tab_id } => {
                println!("{tab_id}: renderer crashed (other tabs unaffected)");
            }
            EngineEvent::EngineShutdown => {
                println!("engine shut down");
                break;
            }
        }
    }
}
