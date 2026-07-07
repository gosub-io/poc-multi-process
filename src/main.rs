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
#[cfg(all(feature = "multi-process", target_os = "linux"))]
mod fork_server;
mod ipc;
mod net_daemon;
mod renderer;
#[cfg(feature = "multi-process")]
mod sandbox;
#[cfg(all(feature = "multi-process", target_os = "linux"))]
mod ring;
#[cfg(all(feature = "multi-process", target_os = "linux"))]
mod selftest;
#[cfg(all(feature = "multi-process", target_os = "linux"))]
mod shm;

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
        // net-daemon <fd> ; renderer <origin> <fd> ; fork-server <control-fd>
        #[cfg(feature = "multi-process")]
        Some("net-daemon") => net_daemon::run(&args[2]),
        #[cfg(feature = "multi-process")]
        Some("renderer") => renderer::run(&args[2], &args[3]),
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        Some("fork-server") => fork_server::run(&args[2]),
        // Internal sandbox self-test, spawned only by the integration suite.
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        Some("selftest") => selftest::run(&args[2]),
        // Tile-transport measurement: render N frames over one tab and report
        // time + engine memory, via shared memory or the socket-copy path.
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        Some("--bench-tiles") => bench_tiles(args.get(2), args.get(3)),
        // Body-transport measurement: fetch one N-MiB body and report time +
        // throughput + engine memory, via the shm ring or the socket copy.
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        Some("--bench-stream") => bench_stream(args.get(2), args.get(3)),
        Some(other) => {
            eprintln!("unknown argument: {other}");
            eprintln!(
                "usage: gosub-proc-iso-poc [--single-process | --multi-process | --bench-tiles <frames> <shm|socket> | --bench-stream <MiB> <ring|socket>]"
            );
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
    // script-visible. Origins are the full scheme://host[:port] tuple, so
    // these cookies can never be attached to an http:// fetch.
    engine.set_cookie(work, "https://example.com", "session", "work-token", true).unwrap();
    engine.set_cookie(work, "https://example.com", "theme", "dark", false).unwrap();
    engine.set_cookie(personal, "https://example.com", "session", "personal-token", true).unwrap();

    // example.com opened in both zones runs as two separate renderer processes
    // bound to (work, example.com) and (personal, example.com).
    engine.open_tab(work, "https://example.com").unwrap();
    engine.open_tab(personal, "https://example.com").unwrap();

    let mut tabs_closed = 0;
    for event in events {
        match event {
            EngineEvent::TabOpened { tab_id, zone, origin } => {
                println!("{tab_id} [{zone}]: opened for {origin}");
                // The personal tab fetches a large (4 MiB) body — the PoC's
                // stand-in for a big download — to exercise the shared-memory
                // ring transport; the work tab fetches a small in-band page.
                // The renderer reports the body transport + round-trip check
                // on stderr.
                let path = if zone == personal { "blob/4" } else { "index.html" };
                // `origin` is already scheme://host[:port].
                engine.navigate(tab_id, format!("{origin}/{path}")).unwrap();
            }
            EngineEvent::FrameReady { tab_id, tile } => {
                println!(
                    "{tab_id}: frame ready — {}x{} ({} KiB via {}, pattern {})",
                    tile.width,
                    tile.height,
                    tile.pixels.len() / 1024,
                    tile.pixels.transport(),
                    if tile_matches_pattern(&tile) { "ok" } else { "MISMATCH" },
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

/// Round-trip acceptance check: the received tile must be byte-identical to
/// the deterministic pattern the renderer rasterizes — over shared memory
/// this proves the engine is reading the very pages the renderer wrote.
fn tile_matches_pattern(tile: &events::Tile) -> bool {
    let px = tile.pixels.as_slice();
    px.len() == tile.width as usize * tile.height as usize * 4
        && px.iter().enumerate().all(|(i, &b)| b == renderer::tile_pattern(i))
}

/// `--bench-tiles <frames> <shm|socket>`: navigate one tab `frames` times in
/// multi-process mode, verifying every tile, and report wall time plus the
/// engine's memory high-water mark — the "measure, don't assume" check that
/// the shared-memory channel actually beats copying tiles through the socket.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn bench_tiles(frames: Option<&String>, transport: Option<&String>) {
    let frames: usize = frames.and_then(|f| f.parse().ok()).unwrap_or(50);
    let transport = transport.map(String::as_str).unwrap_or("shm");
    if !matches!(transport, "shm" | "socket") {
        eprintln!("usage: gosub-proc-iso-poc --bench-tiles <frames> <shm|socket>");
        std::process::exit(2);
    }
    if transport == "socket" {
        // Inherited by the fork server and thus by every forked renderer,
        // forcing the copy-through-the-socket tile path for comparison.
        std::env::set_var("GOSUB_TILE_TRANSPORT", "socket");
    }

    let (engine, events) = engine::start(Mode::Multi);
    engine.open_tab(ZoneId(0), "https://example.com").unwrap();

    let mut rendered = 0usize;
    let mut bytes = 0usize;
    let mut started = std::time::Instant::now();
    for event in events {
        match event {
            EngineEvent::TabOpened { tab_id, .. } => {
                started = std::time::Instant::now(); // exclude spawn cost
                engine.navigate(tab_id, "https://example.com/frame").unwrap();
            }
            EngineEvent::FrameReady { tab_id, tile } => {
                assert!(tile_matches_pattern(&tile), "tile pattern mismatch (frame {rendered})");
                rendered += 1;
                bytes += tile.pixels.len();
                let label = tile.pixels.transport();
                if rendered == frames {
                    let elapsed = started.elapsed();
                    println!(
                        "bench: {rendered} frames of {}x{} ({} MiB of pixels) via {label}",
                        tile.width,
                        tile.height,
                        bytes / (1024 * 1024),
                    );
                    println!(
                        "bench: {:.1} ms total, {:.3} ms/frame, all patterns verified",
                        elapsed.as_secs_f64() * 1e3,
                        elapsed.as_secs_f64() * 1e3 / rendered as f64,
                    );
                    println!("bench: engine {}", vm_stats());
                    engine.close_tab(tab_id).unwrap();
                } else {
                    engine.navigate(tab_id, "https://example.com/frame").unwrap();
                }
            }
            EngineEvent::TabClosed { .. } => engine.shutdown().unwrap(),
            EngineEvent::EngineShutdown => break,
            EngineEvent::TabCrashed { tab_id } => panic!("{tab_id} crashed during bench"),
            other => panic!("unexpected event during bench: {other:?}"),
        }
    }
}

/// `--bench-stream <MiB> <ring|socket>`: fetch one `MiB`-sized body through
/// one tab in multi-process mode and report time, throughput, and the
/// engine's memory high-water mark. Via the ring the body flows net →
/// renderer directly (the engine only forwards an fd); via the socket every
/// byte is copied through the engine — the frame cap limits that path to
/// 12 MiB, which is itself part of the story.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn bench_stream(mib: Option<&String>, transport: Option<&String>) {
    let mib: u64 = mib.and_then(|f| f.parse().ok()).unwrap_or(64);
    match transport.map(String::as_str).unwrap_or("ring") {
        "ring" => {}
        "socket" => {
            if mib > 12 {
                eprintln!("socket transport is bounded by the 16 MiB frame cap; use <= 12 MiB");
                std::process::exit(2);
            }
            // Inherited by the net component: forces the in-band copy path.
            std::env::set_var("GOSUB_BODY_TRANSPORT", "socket");
        }
        _ => {
            eprintln!("usage: gosub-proc-iso-poc --bench-stream <MiB> <ring|socket>");
            std::process::exit(2);
        }
    }

    let (engine, events) = engine::start(Mode::Multi);
    engine.open_tab(ZoneId(0), "https://example.com").unwrap();

    let mut started = std::time::Instant::now();
    for event in events {
        match event {
            EngineEvent::TabOpened { tab_id, .. } => {
                started = std::time::Instant::now(); // exclude spawn cost
                engine.navigate(tab_id, format!("https://example.com/blob/{mib}")).unwrap();
            }
            // The frame only renders after the fetch completed; the renderer
            // verified the body pattern and reported the transport on stderr.
            EngineEvent::FrameReady { tab_id, .. } => {
                let elapsed = started.elapsed();
                println!(
                    "bench: {mib} MiB body fetched in {:.1} ms ({:.0} MiB/s)",
                    elapsed.as_secs_f64() * 1e3,
                    mib as f64 / elapsed.as_secs_f64(),
                );
                println!("bench: engine {}", vm_stats());
                engine.close_tab(tab_id).unwrap();
            }
            EngineEvent::TabClosed { .. } => engine.shutdown().unwrap(),
            EngineEvent::EngineShutdown => break,
            EngineEvent::TabCrashed { tab_id } => panic!("{tab_id} crashed during bench"),
            other => panic!("unexpected event during bench: {other:?}"),
        }
    }
}

/// The engine process's `VmRSS`/`VmHWM` (current and peak resident set) from
/// `/proc/self/status`.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn vm_stats() -> String {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("VmRSS:") || l.starts_with("VmHWM:"))
                .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|_| "memory stats unavailable".into())
}
