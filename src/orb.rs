//! Opaque Response Blocking (ORB) — the successor to CORB, and the response-side
//! counterpart to the HttpOnly and SSRF policies: a decision made in a *trusted*
//! process about what bytes are allowed to enter a renderer's address space.
//!
//! Site isolation puts each origin in its own process so a Spectre gadget in one
//! renderer can only read *its own* address space. That guarantee is only worth
//! anything if cross-origin secrets never get *into* that address space in the
//! first place. But real pages load cross-origin subresources constantly
//! (`<img>`, `<script>`, `<link rel=stylesheet>`, fonts), so the network layer
//! cannot simply refuse them. ORB is the line it draws instead:
//!
//! - **Same-origin** — readable. No cross-origin concern.
//! - **Cross-origin, CORS-approved** — readable. The server opted in (`ACAO`).
//! - **Cross-origin, no-cors, an embeddable media type** (image, script, CSS,
//!   font) — delivered but **opaque**: the renderer can *use* it (paint the
//!   image, run the script) but a real engine gives it no API to read the bytes
//!   back as data.
//! - **Cross-origin, no-cors, a *data* type** (HTML, JSON, XML) or anything not
//!   clearly embeddable — **blocked**: the bytes never reach the renderer. This
//!   is the case that matters. A cross-origin `secret.json` pulled in via
//!   `<img src>` or `<script src>` is exactly how a compromised/again-Spectre
//!   renderer would try to slurp another origin's data; ORB withholds it.
//!
//! This module is the pure decision, so it can be unit-tested exhaustively; the
//! net component supplies the inputs (it sees the response's content type and
//! CORS status) and enforces the verdict.

use crate::ipc::FetchMode;

/// A coarse classification of a response's content type — enough for the ORB
/// decision, which turns on "embeddable media" vs "readable data" vs "the rest".
/// A real implementation sniffs the bytes as well as trusting the header; the
/// PoC classifies by the (synthetic) content type alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeKind {
    /// Legitimately embeddable no-cors: delivered opaque cross-origin.
    Image,
    Script,
    Css,
    Font,
    /// "Data" types a cross-origin page must never be able to read: the whole
    /// reason ORB exists.
    Html,
    Json,
    Xml,
    /// Anything else. ORB is conservative: an unknown type is treated as
    /// potentially-sensitive data and blocked cross-origin no-cors.
    Other,
}

impl MimeKind {
    /// The types that may be *embedded* cross-origin without CORS (and so are
    /// delivered opaque rather than blocked).
    fn is_embeddable(self) -> bool {
        matches!(self, MimeKind::Image | MimeKind::Script | MimeKind::Css | MimeKind::Font)
    }
}

/// The ORB verdict for one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrbDecision {
    /// Deliver the bytes. `opaque` = usable but not readable as data.
    Allow { opaque: bool },
    /// Withhold the bytes entirely.
    Block,
}

/// Decide whether a subresource response may reach the renderer, and if so
/// whether it is readable or opaque.
///
/// - `same_origin` — requester and (final, post-redirect) response origin match.
/// - `mode` — the request's Fetch mode.
/// - `cors_ok` — the server granted CORS read access for this requester (only
///   meaningful when `mode == Cors`).
/// - `mime` — the response's content type classification.
pub fn orb_decide(
    same_origin: bool,
    mode: FetchMode,
    cors_ok: bool,
    mime: MimeKind,
) -> OrbDecision {
    // Same-origin bytes are the renderer's own to read.
    if same_origin {
        return OrbDecision::Allow { opaque: false };
    }
    // Cross-origin, but the server opted in via CORS: readable.
    if matches!(mode, FetchMode::Cors) && cors_ok {
        return OrbDecision::Allow { opaque: false };
    }
    // Cross-origin, no CORS grant. An embeddable media type is delivered opaque
    // (usable, not readable); everything else — data types and unknowns — is
    // withheld. This is the ORB protection.
    if mime.is_embeddable() {
        OrbDecision::Allow { opaque: true }
    } else {
        OrbDecision::Block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_is_always_readable() {
        // Even a data type, even no-cors: your own origin's bytes are yours.
        for mime in [MimeKind::Json, MimeKind::Html, MimeKind::Image, MimeKind::Other] {
            assert_eq!(
                orb_decide(true, FetchMode::NoCors, false, mime),
                OrbDecision::Allow { opaque: false }
            );
        }
    }

    #[test]
    fn cross_origin_data_types_are_blocked_without_cors() {
        // The case ORB exists for: a cross-origin JSON/HTML/XML pulled in
        // no-cors (e.g. via <img>/<script>) never reaches the renderer.
        for mime in [MimeKind::Json, MimeKind::Html, MimeKind::Xml, MimeKind::Other] {
            assert_eq!(orb_decide(false, FetchMode::NoCors, false, mime), OrbDecision::Block);
        }
    }

    #[test]
    fn cross_origin_embeddable_types_are_delivered_opaque() {
        for mime in [MimeKind::Image, MimeKind::Script, MimeKind::Css, MimeKind::Font] {
            assert_eq!(
                orb_decide(false, FetchMode::NoCors, false, mime),
                OrbDecision::Allow { opaque: true }
            );
        }
    }

    #[test]
    fn cors_grant_makes_cross_origin_data_readable() {
        // With CORS mode *and* the server's grant, even a data type is readable.
        assert_eq!(
            orb_decide(false, FetchMode::Cors, true, MimeKind::Json),
            OrbDecision::Allow { opaque: false }
        );
        // ...but CORS mode without the grant does not: a data type is still
        // blocked, an embeddable type is still merely opaque.
        assert_eq!(orb_decide(false, FetchMode::Cors, false, MimeKind::Json), OrbDecision::Block);
        assert_eq!(
            orb_decide(false, FetchMode::Cors, false, MimeKind::Image),
            OrbDecision::Allow { opaque: true }
        );
    }

    #[test]
    fn a_cors_grant_is_ignored_in_no_cors_mode() {
        // cors_ok only counts in Cors mode; a no-cors request cannot read data
        // even if the server would have allowed it.
        assert_eq!(orb_decide(false, FetchMode::NoCors, true, MimeKind::Json), OrbDecision::Block);
    }
}
