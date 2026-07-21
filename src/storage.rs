//! Storage service — the `localStorage`/`IndexedDB` stand-in.
//!
//! Persistent per-origin storage needs the one thing a renderer must not have:
//! filesystem access. So it is a service of its own, spawned from the engine
//! (not the zygote, which denies `openat`) with a filesystem filter, and
//! brokered exactly like the net component — one process, many tabs, keyed by a
//! `(zone, origin)` the *engine* stamps from its own bookkeeping.
//!
//! Two properties make this safe:
//!
//! * **The partition key is not a claim.** The zone and origin come from the
//!   engine's `Tab` record, never from the renderer's message, so a compromised
//!   renderer cannot read another origin's storage by naming it — the same rule
//!   that governs cookies and fetches.
//! * **The renderer's key never reaches a path.** `openat` takes a path pointer
//!   seccomp cannot inspect, so the filter permits opening *any* file; a key
//!   like `../../etc/passwd` would traverse out of the storage directory if it
//!   were spliced into a filename. Instead the `(zone, origin, key)` tuple is
//!   hashed and the *hash* is the filename — no attacker-controlled bytes ever
//!   appear in a path. (Landlock would confine `openat` to the directory at the
//!   syscall level; until then this application-level scoping is the guard.)

use crate::ipc::{Endpoint, StorageOp, StorageRequest, StorageResponse};
use std::path::PathBuf;

/// The directory every stored value lives in. The engine creates it before the
/// service starts (the service's filter has `openat` but not `mkdirat`, and the
/// engine is unconfined), so the service only ever *opens* files here.
pub fn storage_dir() -> PathBuf {
    std::env::temp_dir().join("gosub-storage")
}

/// Create the storage directory. Called by the engine at startup, before the
/// service is spawned.
pub fn ensure_dir() {
    let _ = std::fs::create_dir_all(storage_dir());
}

/// FNV-1a. Not for security — for turning an arbitrary `(zone, origin, key)`
/// into a fixed hex filename so no caller-controlled bytes reach the path.
fn hash(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The path a value is stored at. Composed with length prefixes so distinct
/// tuples cannot alias (e.g. origin `"a"`+key `"b"` vs origin `"ab"`+key `""`),
/// then hashed to a hex name — the filename is pure `[0-9a-f]`, so a hostile
/// key cannot escape the directory.
fn path_for(zone: u64, origin: &str, key: &str) -> PathBuf {
    let mut buf = Vec::new();
    buf.extend_from_slice(&zone.to_le_bytes());
    buf.extend_from_slice(&(origin.len() as u64).to_le_bytes());
    buf.extend_from_slice(origin.as_bytes());
    buf.extend_from_slice(key.as_bytes());
    storage_dir().join(format!("{:016x}.val", hash(&buf)))
}

fn handle(zone: u64, origin: &str, op: StorageOp) -> Option<Vec<u8>> {
    match op {
        StorageOp::Get { key } => std::fs::read(path_for(zone, origin, &key)).ok(),
        StorageOp::Set { key, value } => {
            let _ = std::fs::write(path_for(zone, origin, &key), &value);
            None
        }
    }
}

/// The service loop — transport-agnostic, identical in both modes.
pub fn serve(mut ep: Endpoint) {
    // Loop ends when `recv` errors (engine went away) or on `Shutdown`.
    while let Ok(StorageRequest::Op { request_id, zone, origin, op }) = ep.recv::<StorageRequest>() {
        let value = handle(zone, &origin, op);
        if ep.send(&StorageResponse { request_id, value }).is_err() {
            break;
        }
    }
}

/// Multi-process entry point: adopt the inherited link, confine with a
/// filesystem filter, serve.
#[cfg(feature = "multi-process")]
pub fn run(link: &str) {
    // SAFETY: the engine passed us sole ownership of this inherited channel.
    let ch = unsafe { crate::channel::Channel::from_argv(link) }.expect("storage: bad link arg");
    let ep = Endpoint::from_channel(ch).expect("storage: wrap link");
    // Landlock scopes the service's filesystem to exactly its storage dir — so
    // even a bug that formed a path outside it (the key-hashing is the other
    // guard) cannot open one.
    let dir = storage_dir();
    crate::sandbox::lock_down_service(
        "storage",
        crate::sandbox::ServiceCaps { filesystem: true, device: false },
        &[(dir.as_path(), true)],
    );
    serve(ep);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_tuples_do_not_collide() {
        let a = path_for(0, "a", "b");
        let b = path_for(0, "ab", "");
        let c = path_for(1, "a", "b");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn a_hostile_key_cannot_escape_the_directory() {
        let p = path_for(0, "https://example.com", "../../../../etc/passwd");
        // The filename is a pure hex hash; the only parent is the storage dir.
        assert_eq!(p.parent().unwrap(), storage_dir());
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(name.strip_suffix(".val").unwrap().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
