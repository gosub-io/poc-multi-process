//! Binary entry point for the gosub process-isolation PoC. The engine and all
//! its components live in the library crate (`src/lib.rs`); this file is only
//! the child-role dispatch for re-exec plus a minimal event-driven demo. See
//! the library crate docs for the architecture.

use gosub_proc_iso_poc::engine::{self, Mode};
use gosub_proc_iso_poc::events::{self, EngineEvent, ZoneId};
use gosub_proc_iso_poc::renderer;
// Child-role entry points and the selftest exist only in the multi-process
// build; import them under the same gate the dispatch below uses.
#[cfg(feature = "multi-process")]
use gosub_proc_iso_poc::{decoder, device_service, font, net_daemon, selftest, storage};
#[cfg(all(feature = "multi-process", target_os = "linux"))]
use gosub_proc_iso_poc::{fork_server, vault};

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
        // Ephemeral image decoder: decodes one image and exits (see decoder.rs).
        // On Linux it is forked from the zygote and never takes this path; this
        // is the fork+exec fallback used elsewhere.
        #[cfg(feature = "multi-process")]
        Some("decoder") => decoder::run(&args[2]),
        // Engine-spawned services — filesystem or device capable, so they live
        // outside the zygote with their own filters (see each module).
        #[cfg(feature = "multi-process")]
        Some("storage") => storage::run(&args[2]),
        #[cfg(feature = "multi-process")]
        Some("font") => font::run(&args[2]),
        #[cfg(feature = "multi-process")]
        Some("audio") => device_service::run("audio", &args[2]),
        #[cfg(feature = "multi-process")]
        Some("gpu") => device_service::run("gpu", &args[2]),
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        Some("fork-server") => fork_server::run(&args[2]),
        // The cookie vault: a low-authority in-memory secret store, kept out of
        // the broker (Linux only — see `vault`).
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        Some("vault") => vault::run(&args[2]),
        // Internal sandbox self-test, spawned only by the integration suite.
        #[cfg(feature = "multi-process")]
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
    // Give this engine instance its own storage dir and font file, so parallel
    // runs (the integration suite launches many binaries at once) never share a
    // `/tmp` path and race each other's files. Children inherit these via the
    // environment. Set on the main thread before any thread spawns (so the
    // `set_var` is race-free) and before the broker Landlock below.
    #[cfg(feature = "multi-process")]
    {
        let tmp = std::env::temp_dir();
        let pid = std::process::id();
        std::env::set_var("GOSUB_STORAGE_DIR", tmp.join(format!("gosub-storage-{pid}")));
        std::env::set_var("GOSUB_FONT_FILE", tmp.join(format!("gosub-font-{pid}.dat")));
    }

    // Confine the broker process's filesystem before it spawns anything or loads
    // the cookie jar: it may read and exec (to launch children and load their
    // libraries) but may only *write* beneath the temp dir, so a compromised
    // broker cannot plant persistence or tamper with the user's files. Applied
    // here, on the main thread, so every engine thread and every child inherits
    // it. Done in the binary rather than `engine::start` so unit tests and
    // embedders — which drive the engine directly — are not confined.
    #[cfg(feature = "multi-process")]
    gosub_proc_iso_poc::sandbox::lock_down_broker();

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

    // Counts tabs that have *finished*, however they finished. A crash is an
    // outcome, not a reason to wait forever — see `TabCrashed` below.
    let mut tabs_finished = 0;
    let mut crashed = 0;
    // The work tab, and whether it has already demonstrated a cross-origin
    // renderer swap. After its first frame it navigates cross-origin once, so
    // the demo exercises site isolation's renderer swap end to end.
    let mut work_tab: Option<events::TabId> = None;
    let mut work_swapped = false;
    for event in events {
        match event {
            EngineEvent::TabOpened { tab_id, zone, origin } => {
                println!("{tab_id} [{zone}]: opened for {origin}");
                if zone == work {
                    work_tab = Some(tab_id);
                }
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
                // Site isolation: with `GOSUB_DEMO_SWAP` set, the work tab
                // navigates cross-origin after its first frame. The engine swaps
                // in a fresh renderer for the new origin — two origins never
                // share a process — then renders it, after which we close. The
                // flag keeps the *default* run (and every other integration
                // test that drives it) at its original process count; only the
                // swap's own test opts the extra renderer in. Every other frame
                // just closes its tab.
                let demo_swap = std::env::var_os("GOSUB_DEMO_SWAP").is_some();
                if demo_swap && Some(tab_id) == work_tab && !work_swapped {
                    work_swapped = true;
                    engine.navigate(tab_id, "https://other.example/page").unwrap();
                } else {
                    engine.close_tab(tab_id).unwrap();
                }
            }
            EngineEvent::TabClosed { tab_id } => {
                println!("{tab_id}: closed");
                tabs_finished += 1;
                if tabs_finished == 2 {
                    engine.shutdown().unwrap();
                }
            }
            EngineEvent::OpenTabFailed { url, reason } => {
                println!("could not open {url}: {reason}");
            }
            EngineEvent::TabNavigated { tab_id, origin } => {
                println!("{tab_id}: swapped to a new renderer for {origin}");
            }
            EngineEvent::NavigationFailed { tab_id, reason } => {
                println!("{tab_id}: navigation failed: {reason}");
            }
            EngineEvent::TabCrashed { tab_id } => {
                // A crashed tab is finished too. Counting it is what keeps a
                // dead renderer from hanging the whole run: previously this
                // arm only printed, so `tabs_finished` never reached its
                // target, shutdown was never sent, and the loop blocked
                // forever. That turned any renderer failure — a sandbox gap on
                // an untested libc, say — into a silent hang instead of a
                // fast, loud failure. CI sat for hours on one.
                //
                // The exit code below still reports it, so this terminates
                // *and* fails rather than pretending all is well.
                println!("{tab_id}: renderer crashed (other tabs unaffected)");
                crashed += 1;
                tabs_finished += 1;
                if tabs_finished == 2 {
                    engine.shutdown().unwrap();
                }
            }
            EngineEvent::EngineShutdown => {
                println!("engine shut down");
                break;
            }
        }
    }

    // Best-effort cleanup of this instance's per-run storage/font paths, so the
    // per-PID directories do not accumulate in the temp dir across runs.
    #[cfg(feature = "multi-process")]
    {
        if let Some(dir) = std::env::var_os("GOSUB_STORAGE_DIR") {
            let _ = std::fs::remove_dir_all(std::path::PathBuf::from(dir));
        }
        if let Some(file) = std::env::var_os("GOSUB_FONT_FILE") {
            let _ = std::fs::remove_file(std::path::PathBuf::from(file));
        }
    }

    // Exit non-zero if any renderer died. Without this the demo would report
    // success on a run where nothing rendered, which is exactly the false
    // green the integration tests would then have to catch on their own.
    if crashed > 0 {
        eprintln!("{crashed} renderer(s) crashed — see the sandbox notes in src/sandbox/");
        std::process::exit(1);
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
