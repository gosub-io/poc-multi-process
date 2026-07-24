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
//!
//! The filename hash is **keyed** with a per-run random secret ([`RandomState`],
//! i.e. SipHash) rather than a bare fixed-key hash. That matters because the
//! `key` is fully renderer-controlled: with an unkeyed, invertible hash (FNV,
//! and friends) a compromised renderer could *construct* a key whose filename
//! collides with another origin's slot — the origin string is public and the
//! hash state after a known prefix is solvable — turning "different tuple →
//! different file" into a cross-origin read/write. A keyed PRF the renderer
//! cannot observe makes such a collision unconstructible. The key need not
//! survive a restart: filenames are only meaningful for one service lifetime,
//! the same scope as the in-memory quota (see [`MAX_STORE_BYTES`]).

use crate::ipc::{Endpoint, StorageOp, StorageRequest, StorageResponse};
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::path::PathBuf;

/// Largest single value the store will persist. Values already ride the 16 MiB
/// IPC frame cap, but that bounds one *message*, not disk footprint — a
/// renderer could still write many large values. This caps each one.
pub const MAX_VALUE_BYTES: usize = 5 * 1024 * 1024;

/// Ceiling on the whole store's on-disk size for one service lifetime. Without
/// it a renderer can fill the host disk one bounded `Set` at a time. A real
/// engine keys this per `(zone, origin)` with eviction and persists the
/// accounting; the PoC caps the store as a whole and tracks usage in memory,
/// which is enough to make "fill the disk" impossible while the service runs.
pub const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;

/// The directory every stored value lives in. The engine creates it before the
/// service starts (the service's filter has `openat` but not `mkdirat`, and the
/// engine is unconfined), so the service only ever *opens* files here.
///
/// An engine-chosen per-instance dir when `GOSUB_STORAGE_DIR` is set — the
/// binary sets it so parallel runs (the test suite launches many at once) never
/// share `/tmp` state and race each other's files — inherited by the storage
/// service via the environment; the fixed default otherwise.
pub fn storage_dir() -> PathBuf {
    match std::env::var_os("GOSUB_STORAGE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir().join("gosub-storage"),
    }
}

/// Create the storage directory. Called by the engine at startup, before the
/// service is spawned.
pub fn ensure_dir() {
    let _ = std::fs::create_dir_all(storage_dir());
}

/// The path a value is stored at, under a keyed hash of the `(zone, origin, key)`
/// tuple. `keys` is a per-run [`RandomState`] (SipHash) whose secret the renderer
/// cannot see, so a hostile `key` cannot be crafted to collide its filename with
/// another origin's slot. Every field is length-prefixed before hashing so
/// distinct tuples cannot alias even by accident (origin `"a"`+key `"b"` vs
/// origin `"ab"`+key `""`), and the digest is rendered as pure `[0-9a-f]`, so a
/// hostile key cannot escape the directory either.
fn path_for(keys: &RandomState, zone: u64, origin: &str, key: &str) -> PathBuf {
    let mut h = keys.build_hasher();
    h.write_u64(zone);
    h.write_u64(origin.len() as u64);
    h.write(origin.as_bytes());
    h.write_u64(key.len() as u64);
    h.write(key.as_bytes());
    storage_dir().join(format!("{:016x}.val", h.finish()))
}

/// Decide whether writing `new_len` bytes to a slot currently holding `old`
/// bytes keeps total usage within `cap`, given `used` bytes stored now. Returns
/// the projected new total if admitted, `None` if it would exceed `cap`.
/// Saturating throughout so a hostile length can't wrap the arithmetic.
fn admit_write(used: u64, old: u64, new_len: u64, cap: u64) -> Option<u64> {
    let projected = used.saturating_sub(old).saturating_add(new_len);
    (projected <= cap).then_some(projected)
}

/// Per-service accounting for the store-wide byte budget. `used` is the running
/// total; `sizes` remembers each path's current size so an overwrite is counted
/// as a delta, not a fresh add. In-memory and per service lifetime — see
/// [`MAX_STORE_BYTES`].
struct Quota {
    used: u64,
    sizes: HashMap<PathBuf, u64>,
    /// Per-run secret for the filename hash — see [`path_for`]. Created once when
    /// the service starts and reused for every request, so a given tuple maps to
    /// a stable file for this service lifetime while staying unforgeable.
    keys: RandomState,
}

impl Quota {
    fn new() -> Quota {
        Quota { used: 0, sizes: HashMap::new(), keys: RandomState::new() }
    }
}

fn handle(zone: u64, origin: &str, op: StorageOp, quota: &mut Quota) -> Option<Vec<u8>> {
    match op {
        StorageOp::Get { key } => std::fs::read(path_for(&quota.keys, zone, origin, &key)).ok(),
        StorageOp::Set { key, value } => {
            if value.len() > MAX_VALUE_BYTES {
                eprintln!(
                    "[storage] refused oversize value ({} bytes > {MAX_VALUE_BYTES})",
                    value.len()
                );
                return None;
            }
            let path = path_for(&quota.keys, zone, origin, &key);
            let old = quota.sizes.get(&path).copied().unwrap_or(0);
            let Some(projected) =
                admit_write(quota.used, old, value.len() as u64, MAX_STORE_BYTES)
            else {
                eprintln!("[storage] refused write: store budget exceeded ({MAX_STORE_BYTES} bytes)");
                return None;
            };
            // Only commit the accounting if the write actually landed.
            if std::fs::write(&path, &value).is_ok() {
                quota.used = projected;
                quota.sizes.insert(path, value.len() as u64);
            }
            None
        }
    }
}

/// The service loop — transport-agnostic, identical in both modes.
pub fn serve(mut ep: Endpoint) {
    let mut quota = Quota::new();
    // Loop ends when `recv` errors (engine went away) or on `Shutdown`.
    while let Ok(StorageRequest::Op { request_id, zone, origin, op }) = ep.recv::<StorageRequest>() {
        let value = handle(zone, &origin, op, &mut quota);
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
        // One shared key, as the running service uses: distinct tuples — including
        // the length-prefix aliasing pair (origin "a"+key "b" vs "ab"+"") — land
        // on distinct files, and the same tuple is stable within a run.
        let keys = RandomState::new();
        let a = path_for(&keys, 0, "a", "b");
        let b = path_for(&keys, 0, "ab", "");
        let c = path_for(&keys, 1, "a", "b");
        let d = path_for(&keys, 0, "a", "bc"); // key-length prefix disambiguates
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a, path_for(&keys, 0, "a", "b"));
    }

    #[test]
    fn the_filename_key_is_per_run_not_fixed() {
        // Two independent service lifetimes hash the same tuple under different
        // secrets, so the filename is not a fixed function of the tuple a renderer
        // could invert to construct a cross-origin collision.
        let (k1, k2) = (RandomState::new(), RandomState::new());
        assert_ne!(path_for(&k1, 0, "https://a.example", "k"), path_for(&k2, 0, "https://a.example", "k"));
    }

    #[test]
    fn admit_write_enforces_the_store_budget() {
        // Fresh slot: admitted while it fits, refused once it would exceed.
        assert_eq!(admit_write(0, 0, 100, 1000), Some(100));
        assert_eq!(admit_write(950, 0, 50, 1000), Some(1000)); // exactly at cap
        assert_eq!(admit_write(950, 0, 51, 1000), None); // one over
    }

    #[test]
    fn admit_write_counts_an_overwrite_as_a_delta() {
        // A slot already holding 800 bytes, store full to the brim: rewriting
        // that same slot smaller must be admitted (net frees space), and a
        // same-size rewrite must still fit even though used == cap.
        assert_eq!(admit_write(1000, 800, 200, 1000), Some(400));
        assert_eq!(admit_write(1000, 800, 800, 1000), Some(1000));
        // ...but growing it past what freeing the old value allows is refused.
        assert_eq!(admit_write(1000, 800, 801, 1000), None);
    }

    #[test]
    fn admit_write_saturates_on_hostile_lengths() {
        // A near-u64::MAX length cannot wrap the arithmetic into admitting.
        assert_eq!(admit_write(0, 0, u64::MAX, MAX_STORE_BYTES), None);
    }

    #[test]
    fn a_hostile_key_cannot_escape_the_directory() {
        let keys = RandomState::new();
        let p = path_for(&keys, 0, "https://example.com", "../../../../etc/passwd");
        // The filename is a pure hex hash; the only parent is the storage dir.
        assert_eq!(p.parent().unwrap(), storage_dir());
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(name.strip_suffix(".val").unwrap().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
