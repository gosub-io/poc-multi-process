//! The engine's public command/event vocabulary, mirroring the shape of
//! gosub-engine's `engine/events.rs`: commands flow *in* through an
//! [`EngineHandle`](crate::engine::EngineHandle), events flow *out* of the
//! engine's event loop. Nothing here knows about processes, threads, or
//! sockets — the isolation architecture is entirely below this layer.

/// Identifies a tab for the lifetime of the engine.
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
    pub pixels: Vec<u8>,
}

/// Commands accepted by the engine's event loop.
#[derive(Debug)]
pub enum EngineCommand {
    /// Open a tab for the given URL. Spawns a renderer component for the
    /// URL's origin; answered by [`EngineEvent::TabOpened`].
    OpenTab { url: String },
    /// A command addressed to one tab.
    Tab { tab_id: TabId, cmd: TabCommand },
    /// Store a cookie in the engine's jar (stand-in for `Set-Cookie`
    /// arriving via the net component).
    SetCookie { origin: String, name: String, value: String },
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
    /// A tab (and its per-origin renderer component) is up.
    TabOpened { tab_id: TabId, origin: String },
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
            .field("pixels", &format_args!("{} bytes", self.pixels.len()))
            .finish()
    }
}
