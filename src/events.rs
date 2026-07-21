//! The engine's public command/event vocabulary, mirroring the shape of
//! gosub-engine's `engine/events.rs`: commands flow *in* through an
//! [`EngineHandle`](crate::engine::EngineHandle), events flow *out* of the
//! engine's event loop. Nothing here knows about processes, threads, or
//! sockets — the isolation architecture is entirely below this layer.

/// Identifies a **zone**: a storage/security partition (cookies, localStorage)
/// à la browser profiles / container tabs ("Home", "Work"). All of a zone's
/// tabs share its cookie jar; different zones are isolated. The engine keys
/// per-origin state by `(ZoneId, origin)`, and a renderer process is bound to
/// one `(zone, origin)` so it can never be reused across the partition.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ZoneId(pub u64);

impl std::fmt::Display for ZoneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "zone-{}", self.0)
    }
}

/// Identifies a tab for the lifetime of the engine. A tab lives inside one
/// zone and (in this PoC) hosts a single frame; a real tab is a frame tree
/// that can span several `(zone, origin)` renderer processes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TabId(pub u64);

impl std::fmt::Display for TabId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tab-{}", self.0)
    }
}

/// A rasterized frame produced by a tab's renderer.
pub struct Tile {
    pub width: u32,
    pub height: u32,
    pub pixels: TilePixels,
}

/// How a tile's pixels reached the engine. The compositor-facing API is the
/// same either way (`as_slice`); the variant only records whether the bytes
/// were copied through the IPC message or are a zero-copy view of the
/// renderer's sealed shared-memory buffer. (This is the one place transport
/// shows through this layer — deliberately, so the consumer can composite
/// straight from shared memory without an extra copy.)
pub enum TilePixels {
    /// Copied in-band through the IPC message (local channels, fallback).
    Inline(Vec<u8>),
    /// A read-only mapping of the renderer's sealed memfd (Linux).
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    Shared(crate::shm::TileMapping),
}

impl TilePixels {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            TilePixels::Inline(v) => v,
            #[cfg(all(feature = "multi-process", target_os = "linux"))]
            TilePixels::Shared(m) => m.as_slice(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// Human-readable transport label, used by the demo/bench output (and
    /// asserted by the integration tests).
    pub fn transport(&self) -> &'static str {
        match self {
            TilePixels::Inline(_) => "message copy",
            #[cfg(all(feature = "multi-process", target_os = "linux"))]
            TilePixels::Shared(_) => "shared memory",
        }
    }
}

/// Commands accepted by the engine's event loop.
#[derive(Debug)]
pub enum EngineCommand {
    /// Open a tab in `zone` for the given URL. Spawns a renderer bound to
    /// `(zone, origin)`; answered by [`EngineEvent::TabOpened`].
    OpenTab { zone: ZoneId, url: String },
    /// A command addressed to one tab.
    Tab { tab_id: TabId, cmd: TabCommand },
    /// Store a cookie in a zone's jar (stand-in for `Set-Cookie` arriving via
    /// the net component). Keyed by `(zone, origin)`, so the same origin has
    /// independent cookies in different zones. `http_only` cookies are never
    /// exposed to a renderer — only the net component sees their values.
    SetCookie { zone: ZoneId, origin: String, name: String, value: String, http_only: bool },
    /// Gracefully shut down all components and the event loop; answered by
    /// [`EngineEvent::EngineShutdown`].
    Shutdown,
}

/// Commands addressed to a single tab.
#[derive(Debug)]
pub enum TabCommand {
    /// Navigate the tab and produce a frame; answered by
    /// [`EngineEvent::FrameReady`] (or `NavigationFailed`).
    ///
    /// Because renderers are per-origin (site isolation), a navigation must
    /// stay within the tab's origin — a real engine would swap in a renderer
    /// for the new origin instead.
    Navigate { url: String },
    /// Close the tab and its renderer; answered by [`EngineEvent::TabClosed`].
    Close,
}

/// Events emitted by the engine's event loop.
#[derive(Debug)]
pub enum EngineEvent {
    /// A tab (and its `(zone, origin)` renderer component) is up.
    TabOpened { tab_id: TabId, zone: ZoneId, origin: String },
    /// `OpenTab` could not be honored (e.g. unparseable URL).
    OpenTabFailed { url: String, reason: String },
    /// A renderer delivered a frame for its tab.
    FrameReady { tab_id: TabId, tile: Tile },
    /// A navigation was refused (e.g. cross-origin for this tab's renderer).
    NavigationFailed { tab_id: TabId, reason: String },
    /// The tab's renderer went away without being asked to (in multi-process
    /// mode: the child process crashed; other tabs are unaffected).
    TabCrashed { tab_id: TabId },
    /// A tab was closed on request.
    TabClosed { tab_id: TabId },
    /// The engine has shut down; no further events follow.
    EngineShutdown,
}

impl std::fmt::Debug for Tile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tile")
            .field("width", &self.width)
            .field("height", &self.height)
            .field(
                "pixels",
                &format_args!("{} bytes via {}", self.pixels.len(), self.pixels.transport()),
            )
            .finish()
    }
}
