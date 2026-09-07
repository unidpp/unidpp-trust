//! UniDPP trust-list service (crate `unidpp-trust`).
//!
//! Part of UniDPP (github.com/unidpp) — implements TODO.impl
//! `10-remaining-tasks-definitive.md` item 20: a running trust-list
//! service so a verdict verifier **fetches live trust state**
//! instead of embedding fixtures. The model and semantics come
//! verbatim from `unidpp-signatif`:
//!
//! - **delegation trust graph** — root / threshold-group / delegated /
//!   end nodes with parent-signed, scope-narrowing delegation
//!   credentials ([`unidpp_signatif::graph`]);
//! - **jurisdiction trust lists** with `not_before` / `superseded_at`
//!   entry windows ([`unidpp_signatif::graph::TrustList`]);
//! - **M-of-K master list** — multiple independent log witnesses
//!   attesting roots, with a quorate acceptance rule
//!   ([`unidpp_signatif::graph::MasterList`]);
//! - **revocation ledger** — reason taxonomy whose decisive property
//!   is [`unidpp_signatif::revoke::RevocationReason::is_retroactive`]:
//!   prospective reasons keep prior as-of verifications valid (like
//!   code signing); retroactive reasons (misissuance, fraud,
//!   authority-compromised) void ab initio within the explicit
//!   distrust window `[start, end]` and re-validate outside it
//!   ([`unidpp_signatif::revoke::RevocationLedger`]).
//!
//! Server conventions mirror the unidpp house pattern (`unidpp-registry`,
//! `unidpp-resolver`, `unidpp-issuer`): axum over tokio,
//! dependency-light, JSONL append-only journal replayed on start,
//! Bearer-guarded admin, `x-as-of` stamp on every response.
//!
//! - **Signed responses.** Every JSON body is signed by the service
//!   keyring in [`unidpp_signatif::sign::SigningDomain::TreeHead`] —
//!   the closest documented SIGNATIF precedent (operator's signed
//!   statement of state); the SIGNATIF domain table has no
//!   service-response slot. Two signature headers (`x-sig-ed25519`,
//!   `x-sig-ecdsa-p256`) carry both suites so a verifier restricted
//!   to P-256 only (the EU profile) still verifies. The body bytes
//!   themselves are the payload; identical bodies produce identical
//!   signatures (Ed25519 deterministic + RFC 6979 ECDSA), so a
//!   strong `ETag` is set automatically and `cache-control: immutable`
//!   is honest for point-in-time (`?at=`) responses.
//! - **Seed fixtures derived from signatif's tests** — the trust
//!   graph, trust list, master list, and revocation ledger are
//!   minted from the same seeded keys used by
//!   `unidpp-signatif/tests/common::topology` and
//!   `unidpp-signatif/tests/scenario_misissuance`. Verdict verifiers
//!   can replay the signatif scenarios against this service
//!   bit-for-bit.
//! - **JSONL journal** for durability and audit (`Store::open` +
//!   `AuditRecord::to_json`); the seed ops are journaled as ordinary
//!   records, so restart replay is exact.
//! - **Adapter notes** are surfaced in `/keyring`, `/`, and the rustdoc
//!   here — see `wire.rs` for the `PublicKey` serde-asymmetry note
//!   (Display prints a sha256 fingerprint, `from_bytes` expects raw
//!   key bytes; we use the raw-bytes path everywhere).

#![warn(rustdoc::broken_intra_doc_links)]
// Handlers and parse helpers return `Result<_, Response>` with the
// ready-made error response by value — the idiomatic axum pattern;
// boxing the error would complicate every call site for no gain.
#![allow(clippy::result_large_err)]

pub mod api;
pub mod hex;
pub mod keyring;
pub mod seed;
pub mod store;
pub mod time;
pub mod wire;

pub use api::{run, Config, TestServer};
pub use hex::{hex_decode, hex_encode};
pub use keyring::{Keyring, KeyringMode, Role};
pub use store::{AuditRecord, Op, Store, StoreError};
pub use time::Timestamp;
