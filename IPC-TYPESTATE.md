# IPC protocol design: from bincode enums to a typestate protocol

**Status: proposal / RFC.** Nothing here is implemented yet. This note captures
the argument for *not* adopting an external IDL, and for instead tightening the
IPC contract inside Rust's own type system. It is a decision aid, not a record
of a measure in effect — contrast with [SECURITY-MEASURES.md](SECURITY-MEASURES.md),
which describes only what the code actually does.

---

## 0. The question this answers

> We use bincode for IPC. Other engines use an IDL (Mojo, IPDL). Should we?

Short answer: **no external IDL, but yes to modelling the protocol as types.**
The value the big engines extract from their IDLs is mostly *not* the wire
format, and the part that is valuable (protocol state machines) is reachable in
Rust without a code-generation toolchain.

---

## 1. What we already have

The message enums in [`src/ipc.rs`](src/ipc.rs) — `FromRenderer`, `ToRenderer`,
`NetRequest`, `NetResponse`, `StorageRequest`, … — **are the IDL.** The serde
`#[derive(Serialize, Deserialize)]` is the code generator. bincode is only the
*codec* (the byte encoding), framed length-prefixed by
[`ipc::send_msg`/`recv_msg`](src/ipc.rs) with a `MAX_FRAME_LEN` guard and a fuzz
target (`recv_msg_never_panics_on_arbitrary_frames`).

So "adopt an IDL" is a false choice — we have one, expressed in Rust types. The
real question is whether to move that schema *out* of Rust into a separate
`.mojom`/`.ipdl` file with its own build step, and whether to strengthen it.

## 2. What the big engines actually get from their IDLs

| Engine | IDL | Primary value |
|---|---|---|
| Chromium | Mojo (`.mojom`) | **Cross-language bindings** — C++ ↔ JS ↔ Java. Their processes are not all one language. |
| Firefox | IPDL (`.ipdl`) | **Protocol state machine** — message directionality, which messages are legal in which state, sync/async discipline, actor lifetimes, all compiler-checked. |
| WebKit | `.messages.in` | Codegen convenience over hand-written marshalling. |

The wire encoding is the least important thing any of them buys from its IDL.

## 3. Why an external IDL is the wrong buy *here*

Two facts about this codebase cut against it:

1. **All Rust, single binary.** [`src/main.rs`](src/main.rs) re-execs itself with
   a role argument (`renderer <origin> <link>`, `net-daemon <link>`). Both ends
   of every link are the *identical build* — same struct layouts, guaranteed.
   The two headline IDL benefits — cross-language bindings and cross-version
   schema evolution — give us almost nothing, because there is never a version
   skew across the boundary. bincode's real weaknesses (non-self-describing,
   positional enum tags that silently change meaning on reorder) do not bite for
   the same reason: the encoder and decoder are compiled from one source of
   truth.

2. **The codec seam is already hardened.** Length framing, `MAX_FRAME_LEN`, the
   fuzz target, and the `SCM_RIGHTS` fd-count validation in
   [`ipc::recv_fd`](src/ipc.rs) all live below the message layer. An IDL adds
   nothing to any of it.

Importing Mojo-style tooling would mainly buy a build step and a second source
of truth to keep in sync with the Rust.

## 4. The actual gap: wrong-type and wrong-time messages

Look at every exchange in [`renderer.rs::render_page`](src/renderer.rs) (lines
84–244). Each is: send one `FromRenderer`, `recv::<ToRenderer>()`, then a match
whose non-matching arms collapse to `_ => {}` or `_ => None`. For example
(`renderer.rs:116-120`):

```rust
ep.send(&FromRenderer::NeedCookies { origin: origin.to_string() })?;
let _cookies = match ep.recv::<ToRenderer>()? {
    ToRenderer::Cookies(cookies) => cookies,
    _ => None,                       // ← engine could send ANY ToRenderer here
};
```

Those throwaway arms *are* the hole. Two things are conflated in the enums:

- **Direction.** `ToRenderer` mixes *commands* the engine pushes (`RenderPage`,
  `Shutdown`) with *replies* to renderer requests (`FetchResult`, `Cookies`, …).
  The `serve` loop (`renderer.rs:70-81`) must `_ => {}` every reply variant
  because they are legal inbound at the type level but meaningless there.
- **Pairing.** Nothing ties `NeedFetch` to "the reply is a fetch result." The
  pairing lives only in the match arms, so a buggy or compromised engine
  answering `NeedFetch` with `Cookies` is silently swallowed.

The fix is to make the type system carry the contract. Two tiers.

## 5. Tier 1 — split by direction, pair request ⇄ reply

Cheap, mechanical, and it deletes every `_ => {}`. Introduce a trait that pairs
each request with the one reply type it admits:

```rust
/// A renderer→engine message that expects exactly one reply of a known type.
pub trait Request: Serialize {
    type Reply: DeserializeOwned;
}

pub struct NeedFetch { pub url: String }
pub enum FetchReply {
    Body   { status: u16, body: Vec<u8> },
    Stream { status: u16, body_len: u64 },   // Linux: SCM_RIGHTS fd follows
    Denied { reason: String },
}
impl Request for NeedFetch { type Reply = FetchReply; }

pub struct NeedCookies { pub origin: String }
impl Request for NeedCookies { type Reply = Option<Vec<(String, String)>>; }

pub struct NeedDecode { pub image: Vec<u8> }
impl Request for NeedDecode { type Reply = DecodeOutcome; }

pub struct NeedStorage { pub op: StorageOp }
impl Request for NeedStorage { type Reply = Option<Vec<u8>>; }
// …NeedFont, NeedSubresource likewise
```

The engine→renderer *command* channel becomes its own type, with no reply
variants left to ignore:

```rust
/// The only things the engine may push at a renderer unprompted.
pub enum Command {
    RenderPage { url: String },
    Shutdown,
}
```

One helper folds send-then-typed-recv so the call site cannot name the wrong
reply:

```rust
impl Endpoint {
    /// Send a request, receive exactly its declared reply. There is no
    /// "wrong reply" arm to write — the type is the contract.
    pub fn ask<R: Request>(&mut self, req: R) -> io::Result<R::Reply> {
        self.send(&req)?;
        self.recv::<R::Reply>()
    }
}
```

The cookie exchange above collapses to a line with no fallback arm:

```rust
let _cookies = ep.ask(NeedCookies { origin: origin.to_string() })?;
```

And `serve` matches `Command` — the `_ => {}` is gone because a `FetchReply` can
no longer even be *named* on that channel. The engine side changes symmetrically:
it answers a `NeedFetch` with `FetchReply::Body`, and the compiler forbids it
from sending a `Cookies` reply in that slot.

**Wire impact:** none of substance. Still bincode frames. `FetchReply` is an
enum, so serde tags it as before; single-shape replies (cookies, storage) shed
even that discriminant. The contract simply moves from match arms into types.

## 6. Tier 2 — typestate for ordering (the IPDL property, no codegen)

Tier 1 stops *wrong-type* replies. Tier 2 stops *wrong-time* messages: a second
request issued before the first reply is read, or a reply read with nothing
outstanding. Model the endpoint as states that consume `self`:

```rust
pub struct Idle { ep: Endpoint }
pub struct Awaiting<R: Request> { ep: Endpoint, _r: PhantomData<R> }

impl Idle {
    /// Sending a request moves you out of Idle — you now owe a receive.
    pub fn ask<R: Request>(mut self, req: R) -> io::Result<Awaiting<R>> {
        self.ep.send(&req)?;
        Ok(Awaiting { ep: self.ep, _r: PhantomData })
    }
}

impl<R: Request> Awaiting<R> {
    /// The only path back to Idle is to consume the reply. You cannot ask again
    /// while one is outstanding, nor receive with none outstanding.
    pub fn reply(mut self) -> io::Result<(R::Reply, Idle)> {
        let r = self.ep.recv::<R::Reply>()?;
        Ok((r, Idle { ep: self.ep }))
    }
}
```

`render_page` then reads as a chain that will not compile if the cadence breaks:

```rust
let st = Idle { ep };
let (_doc,     st) = st.ask(NeedFetch { url })?.reply()?;
let (_cookies, st) = st.ask(NeedCookies { origin })?.reply()?;
let (_decoded, st) = st.ask(NeedDecode { image })?.reply()?;
// forgetting a .reply() leaves you holding an Awaiting — you literally cannot
// .ask() the next request, so the mistake is a compile error, not a deadlock.
```

This is exactly the state-machine guarantee Firefox's IPDL generates from
`.ipdl` files, obtained from Rust move semantics instead of a codegen step.

## 7. Costs and where it frays

- **fd follow-ups.** `FetchReply::Stream` and the tile's `TileShm` still need an
  explicit `recv_fd()` after the typed reply (see `renderer.rs:96-98`,
  `renderer.rs:253-278`). Typestate pairs the *message*, not the trailing
  `SCM_RIGHTS` byte. Keep the fd receive explicit and visible rather than hiding
  it in reply decoding.
- **Async multiplexing.** Tier 2's consume-`self` model assumes a synchronous
  request→reply cadence — which is exactly what the renderer↔engine link is. The
  service links (`NetRequest`, `StorageRequest`) interleave many tabs over one
  socket via `request_id`; those want a correlation map, not typestate. **Apply
  Tier 2 only to the renderer link; leave the multiplexed service links at
  Tier 1.**
- **Boilerplate.** Roughly one `impl Request` per exchange. A small declarative
  macro (`request!(NeedFetch => FetchReply)`) removes it without a build step.

## 8. Recommendation and rollout

1. **Tier 1 across all links.** Mechanical refactor; deletes every silent
   `_ => {}`/`_ => None` reply arm and is the bulk of the safety win. Touches
   `ipc.rs`, `renderer.rs`, `engine.rs`, and the service loops.
2. **Tier 2 on the renderer link only**, where the synchronous cadence fits.
3. **Keep serde types as the schema of record and bincode as the codec.** If a
   self-describing wire is ever wanted (it is not today), the cheap swap is
   [`postcard`](https://docs.rs/postcard) over the same serde types — still not
   an external IDL.

Non-goal: adopting Mojo/IPDL-style `.idl` files and their generators. For a
single-binary, all-Rust engine they solve problems this codebase does not have.
