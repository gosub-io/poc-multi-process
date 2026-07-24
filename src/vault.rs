//! The **vault** — a low-authority, in-memory cookie store, kept *out* of the
//! broker (Linux).
//!
//! The governing principle is that no one process should hold both large secrets
//! *and* a large hostile-input surface. The broker deserializes untrusted IPC
//! frames, so the secrets must leave it — and the biggest secret is the cookie
//! jar. The vault is where it goes: a process with the **least authority of any
//! in the model** — its filter is the bare content baseline (no network, no
//! `openat`, no `ioctl`; just I/O on existing fds and memory), and it holds no
//! filesystem or device capability at all. Even if compromised it can only
//! answer the narrow queries below; it cannot exfiltrate directly.
//!
//! Two properties, mirroring storage:
//!
//! * **Identity is not a claim.** The `(zone, origin)` on every request is
//!   stamped by the *broker* from its own bookkeeping (or carried on the
//!   broker-stamped `NetRequest` the net component acts on), never by a renderer.
//! * **HttpOnly is enforced here.** A `Get { visible_only: true }` returns only
//!   the non-HttpOnly cookies — the `document.cookie` view — so an exploited
//!   renderer never sees its origin's session token. The full set
//!   (`visible_only: false`) is only ever returned to the net component, to
//!   attach to an outbound request; it never travels to a renderer.
//!
//! In-memory only: the jar does not survive a vault restart (a respawned vault
//! starts empty). That keeps the vault's filter maximally tight — no filesystem
//! — which is the property being demonstrated; a production vault would persist,
//! trading some of that tightness for durability. Linux-only, like the fork
//! server / shm / ring it shares fd-passing machinery with.

use crate::ipc::{Endpoint, VaultRequest, VaultResponse};
use std::collections::HashMap;

/// One stored cookie. `http_only` is what gates the `document.cookie` view.
struct Cookie {
    name: String,
    value: String,
    http_only: bool,
}

/// The in-memory jar, partitioned by `(zone, origin)` so the same origin in two
/// zones has independent cookies — the profile/container split.
#[derive(Default)]
struct Jar {
    by_partition: HashMap<(u64, String), Vec<Cookie>>,
}

impl Jar {
    fn set(&mut self, zone: u64, origin: String, name: String, value: String, http_only: bool) {
        self.by_partition.entry((zone, origin)).or_default().push(Cookie {
            name,
            value,
            http_only,
        });
    }

    /// The cookies for a partition. `visible_only` filters to the non-HttpOnly
    /// set (`document.cookie`); otherwise the full attachable set.
    fn get(&self, zone: u64, origin: &str, visible_only: bool) -> Vec<(String, String)> {
        self.by_partition
            .get(&(zone, origin.to_string()))
            .map(|cs| {
                cs.iter()
                    .filter(|c| !visible_only || !c.http_only)
                    .map(|c| (c.name.clone(), c.value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The service loop — transport-agnostic. `Set` is fire-and-forget; `Get`
/// replies with the partition's cookies.
pub fn serve(mut ep: Endpoint) {
    let mut jar = Jar::default();
    // Loop ends when `recv` errors (peer gone) or on `Shutdown`.
    while let Ok(req) = ep.recv::<VaultRequest>() {
        match req {
            VaultRequest::Shutdown => break,
            VaultRequest::Set { zone, origin, name, value, http_only } => {
                jar.set(zone, origin, name, value, http_only);
            }
            VaultRequest::Get { request_id, zone, origin, visible_only } => {
                let cookies = jar.get(zone, &origin, visible_only);
                if ep.send(&VaultResponse { request_id, cookies }).is_err() {
                    break;
                }
            }
        }
    }
}

/// Multi-process entry point: adopt the inherited link, confine to the tightest
/// filter in the model (bare baseline — no network, files, devices), then serve.
#[cfg(feature = "multi-process")]
pub fn run(link: &str) {
    // SAFETY: the engine passed us sole ownership of this inherited channel.
    let ch = unsafe { crate::channel::Channel::from_argv(link) }.expect("vault: bad link arg");
    let ep = Endpoint::from_channel(ch).expect("vault: wrap link");
    crate::sandbox::lock_down_vault();
    serve(ep);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(jar: &mut Jar, zone: u64, origin: &str, name: &str, value: &str, http_only: bool) {
        jar.set(zone, origin.to_string(), name.to_string(), value.to_string(), http_only);
    }
    fn pair(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn partitions_by_zone_and_origin_and_hides_http_only() {
        let mut jar = Jar::default();
        set(&mut jar, 0, "example.com", "session", "work-token", true); // HttpOnly
        set(&mut jar, 0, "example.com", "theme", "dark", false);
        set(&mut jar, 1, "example.com", "session", "personal-token", true); // other zone

        // Attachable (network) set includes HttpOnly; scoped to (zone, origin).
        assert_eq!(
            jar.get(0, "example.com", false),
            vec![pair("session", "work-token"), pair("theme", "dark")]
        );
        // A different zone is a different partition.
        assert_eq!(jar.get(1, "example.com", false), vec![pair("session", "personal-token")]);

        // The document.cookie view hides HttpOnly.
        assert_eq!(jar.get(0, "example.com", true), vec![pair("theme", "dark")]);
        assert!(jar.get(1, "example.com", true).is_empty()); // only an HttpOnly cookie there

        // Unknown partitions are empty, never another partition's cookies.
        assert!(jar.get(2, "example.com", false).is_empty());
        assert!(jar.get(0, "other.com", false).is_empty());
    }
}
