//! Integration tests: real HTTP against servers spawned on ephemeral
//! ports. Covers the required behaviours: multi-suite signed
//! responses (verification of the exact body bytes against the
//! published anchors, in both suites; tampering rejection; stable
//! ETags for point-in-time queries), jurisdiction trust lists
//! (point-in-time force, withdrawal, filters), the M-of-K master list
//! (witnesses listed, live per-attestation verification, quorum
//! flips), live reason→retroactivity revocation semantics (void ab
//! initio inside explicit windows, re-validation outside, evidentiary
//! cutoffs that keep prior as-of verifications valid for prospective
//! reasons and pre-declaration knowledge, quorum enforcement on
//! declarations), admin auth, and journal replay across restarts.
//! Finally: a verdict verifier fetches live state (graph +
//! anchor bundle), reconstructs the signatif objects, and resolves a
//! trust path — the "verifier embeds fixtures" → "verifier fetches
//! live trust state" transition this service exists for.

mod support;

use std::collections::BTreeMap;

use serde_json::{json, Value};
use support::{enc, get, json_of, json_request};
use unidpp_model::Interval;
use unidpp_signatif::graph::{
    AnchorBundle, MasterList, MasterListEntry, NodeId, TrustGraph, TrustList,
};
use unidpp_signatif::keyring::{KeyId, KeyPair, PublicKey};
use unidpp_signatif::revoke::{QuorumAttestation, Revocation, RevocationReason, RevokedSubject};
use unidpp_signatif::scope::ScopeRequest;
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};
use unidpp_trust::hex::{hex_decode, hex_encode};
use unidpp_trust::wire::{
    edge_from_value, node_from_value, revocation_to_value, witness_attestation_from_value,
};
use unidpp_trust::{Config, TestServer, Timestamp};

/// The seed fixture epoch (mirrors unidpp-signatif's `T0`).
const T0: i64 = 1_000_000;

fn t(offset: i64) -> String {
    Timestamp::from_secs(T0 + offset).to_string()
}

fn t_model(offset: i64) -> unidpp_model::Timestamp {
    unidpp_model::Timestamp::from_secs(T0 + offset)
}

/// The seeded issuer key (same seed as signatif's scenario fixtures).
fn issuer_key() -> KeyPair {
    KeyPair::seeded(Suite::Ed25519, b"scenario/issuer-a").unwrap()
}

/// The seeded quorum members (mirrors scenario_misissuance).
fn quorum_members() -> Vec<KeyPair> {
    vec![
        KeyPair::seeded(Suite::Ed25519, b"scenario/quorum-1").unwrap(),
        KeyPair::seeded(Suite::Ed25519, b"scenario/quorum-2").unwrap(),
        KeyPair::seeded(Suite::EcdsaP256, b"scenario/quorum-3").unwrap(),
    ]
}

async fn spawn_open() -> TestServer {
    TestServer::spawn(Config::default())
        .await
        .expect("spawn server")
}

async fn post(base: &str, path: &str, body: &Value, token: Option<&str>) -> support::HttpResponse {
    support::json_request(
        "POST",
        &format!("{base}{path}"),
        Some(&body.to_string()),
        token,
    )
    .await
}

/// Verify a response's signature headers against the keyring anchors,
/// in the given suite, over the exact body bytes.
fn verify_signature(
    resp: &support::HttpResponse,
    public: &PublicKey,
    header: &str,
) -> Result<(), String> {
    let sig_hex = resp.header(header).ok_or("missing signature header")?;
    let sig = hex_decode(sig_hex).map_err(|e| e.to_string())?;
    let slot = SignatureSlot {
        suite: public.suite(),
        key_id: KeyId::of(public),
        signature: Some(sig),
    };
    slot.verify(SigningDomain::TreeHead, &resp.body, public)
        .map_err(|e| e.to_string())
}

/// The verifier's pinned anchors, fetched live from `/keyring`.
fn anchors_of(keyring: &Value) -> (PublicKey, PublicKey) {
    let ed = hex_decode(keyring["roles"]["sign-ed25519"]["public"].as_str().unwrap()).unwrap();
    let p = hex_decode(
        keyring["roles"]["sign-ecdsa-p256"]["public"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    (
        PublicKey::from_bytes(&ed).unwrap(),
        PublicKey::from_bytes(&p).unwrap(),
    )
}

// ---------------------------------------------------------------------------
// Discovery, keyring, anchors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_healthz_and_keyring_anchors() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let resp = get(&format!("{base}/")).await;
    assert_eq!(resp.status, 200);
    let doc = json_of(&resp);
    assert_eq!(doc["service"], "unidpp-trust");
    assert_eq!(doc["signing"]["domain"], "tree-head");
    assert_eq!(
        doc["revocation_semantics"]["retroactive_reasons"][0],
        "misissuance"
    );
    assert_eq!(get(&format!("{base}/healthz")).await.status, 200);
    assert_eq!(
        json_of(&get(&format!("{base}/healthz")).await)["status"],
        "ok"
    );

    // The keyring publishes both suites with CLI-anchor-compatible
    // raw public keys (32-byte Ed25519 / 65-byte SEC1 P-256).
    let resp = get(&format!("{base}/keyring")).await;
    assert_eq!(resp.status, 200);
    let keyring = json_of(&resp);
    assert_eq!(keyring["mode"], "seeded-dev");
    assert_eq!(keyring["roles"]["sign-ed25519"]["public_len"], 32);
    assert_eq!(keyring["roles"]["sign-ecdsa-p256"]["public_len"], 65);
    assert_eq!(keyring["roles"]["sign-ed25519"]["suite"], "ed25519");
    assert!(keyring["warning"].as_str().unwrap().contains("seeded-dev"));
    let (ed, p256) = anchors_of(&keyring);
    assert_eq!(ed.suite(), Suite::Ed25519);
    assert_eq!(p256.suite(), Suite::EcdsaP256);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Signed responses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn responses_are_signed_in_both_suites_over_exact_body() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let keyring = json_of(&get(&format!("{base}/keyring")).await);
    let (ed_anchor, p256_anchor) = anchors_of(&keyring);

    let resp = get(&format!("{base}/trust-lists")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("x-sig-domain"), Some("tree-head"));
    assert!(Timestamp::parse(resp.header("x-as-of").unwrap()).is_ok());
    // The Ed25519 signature header's key id matches the anchor.
    assert_eq!(
        resp.header("x-sig-key-id-ed25519").unwrap(),
        keyring["roles"]["sign-ed25519"]["key_id"].as_str().unwrap()
    );
    assert_eq!(
        resp.header("x-sig-key-id-ecdsa-p256").unwrap(),
        keyring["roles"]["sign-ecdsa-p256"]["key_id"]
            .as_str()
            .unwrap()
    );

    // Both suites verify over the exact body bytes.
    verify_signature(&resp, &ed_anchor, "x-sig-ed25519")
        .expect("Ed25519 signature verifies over the body");
    verify_signature(&resp, &p256_anchor, "x-sig-ecdsa-p256")
        .expect("ECDSA-P256 signature verifies over the body");

    // Tampering one body byte breaks both.
    let mut tampered = resp.clone();
    let orig = tampered.body.clone();
    let last = tampered.body.len() - 1;
    tampered.body[last] ^= 0x01;
    assert!(verify_signature(&tampered, &ed_anchor, "x-sig-ed25519").is_err());
    assert!(verify_signature(&tampered, &p256_anchor, "x-sig-ecdsa-p256").is_err());
    // And the original still verifies (the tamper was local).
    let mut check = resp.clone();
    check.body = orig;
    assert!(verify_signature(&check, &ed_anchor, "x-sig-ed25519").is_ok());

    server.stop().await;
}

#[tokio::test]
async fn point_in_time_responses_are_stable_and_immutable() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // Current-state: short cache, must-revalidate.
    let resp = get(&format!("{base}/trust-lists")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.header("cache-control"),
        Some("public, max-age=30, must-revalidate")
    );

    // Point-in-time: immutable + stable body → stable signature →
    // stable ETag across repeated requests.
    let url = format!("{base}/trust-lists?at={}", enc(&t(6_000)));
    let a = get(&url).await;
    let b = get(&url).await;
    assert_eq!(a.status, 200);
    assert_eq!(b.status, 200);
    assert_eq!(
        a.header("cache-control"),
        Some("public, max-age=86400, immutable")
    );
    assert_eq!(a.body, b.body, "same query → byte-identical body");
    assert_eq!(a.header("etag"), b.header("etag"), "stable etag");
    assert_eq!(
        a.header("x-sig-ed25519"),
        b.header("x-sig-ed25519"),
        "deterministic signature over the same body"
    );

    // A different `at` yields a different etag (no false sharing).
    let c = get(&format!("{base}/trust-lists?at={}", enc(&t(7_000)))).await;
    assert_ne!(a.header("etag"), c.header("etag"));

    // Errors carry no-store.
    let err = get(&format!("{base}/trust-lists/nope")).await;
    assert_eq!(err.status, 404);
    assert_eq!(err.header("cache-control"), Some("no-store"));

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Trust lists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trust_lists_point_in_time_and_withdrawal() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // Seeded EU list (framework espr) trusts eu-root from T0.
    let resp = get(&format!("{base}/trust-lists")).await;
    let doc = json_of(&resp);
    assert_eq!(doc["count"], 1);
    let list = &doc["trust_lists"][0];
    assert_eq!(list["jurisdiction"], "EU");
    assert_eq!(list["framework"], "espr");
    assert_eq!(list["entries"].as_array().unwrap().len(), 1);
    assert_eq!(list["entries"][0]["node"], "eu-root");
    assert_eq!(list["entries"][0]["not_before"], t(0));
    assert_eq!(list["entries"][0]["in_force_at_as_of"], true);

    // Framework and jurisdiction filters.
    assert_eq!(
        json_of(&get(&format!("{base}/trust-lists?framework={}", enc("espr"))).await)["count"],
        1
    );
    assert_eq!(
        json_of(&get(&format!("{base}/trust-lists?framework={}", enc("batt"))).await)["count"],
        0
    );
    assert_eq!(
        json_of(&get(&format!("{base}/trust-lists?jurisdiction={}", enc("eu"))).await)["count"],
        1,
        "jurisdiction filter is case-insensitive"
    );

    // Point-in-time: before the entry's not_before, not in force.
    let doc = json_of(&get(&format!("{base}/trust-lists/EU?at={}", enc(&t(-1)))).await);
    assert_eq!(doc["entries"][0]["in_force_at_as_of"], false);
    let doc = json_of(&get(&format!("{base}/trust-lists/EU?at={}", enc(&t(0)))).await);
    assert_eq!(doc["entries"][0]["in_force_at_as_of"], true);

    // One jurisdiction's list; unknown jurisdiction 404s.
    assert_eq!(
        json_of(&get(&format!("{base}/trust-lists/eu")).await)["jurisdiction"],
        "EU"
    );
    assert_eq!(get(&format!("{base}/trust-lists/XX")).await.status, 404);

    // Withdrawal: superseded_at closes the entry from that moment.
    let resp = post(
        base,
        "/trust-lists/EU/entries",
        &json!({"node": "eu-root", "not_before": t(0), "superseded_at": t(20_000)}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201);
    let doc = json_of(&get(&format!("{base}/trust-lists/EU?at={}", enc(&t(25_000)))).await);
    assert_eq!(doc["entries"][0]["in_force_at_as_of"], false);
    assert_eq!(doc["entries"][0]["superseded_at"], t(20_000));
    // And still in force one second before the withdrawal.
    let doc = json_of(&get(&format!("{base}/trust-lists/EU?at={}", enc(&t(19_999)))).await);
    assert_eq!(doc["entries"][0]["in_force_at_as_of"], true);

    // Registering a duplicate list conflicts; malformed input is 400.
    assert_eq!(
        post(base, "/trust-lists", &json!({"jurisdiction": "EU"}), None)
            .await
            .status,
        409
    );
    assert_eq!(
        post(base, "/trust-lists", &json!({"framework": "x"}), None)
            .await
            .status,
        400
    );
    // Entry on a missing list 404s.
    assert_eq!(
        post(
            base,
            "/trust-lists/XX/entries",
            &json!({"node": "n", "not_before": t(0)}),
            None
        )
        .await
        .status,
        404
    );

    // A new jurisdiction's list registers (with inline entries).
    let resp = post(
        base,
        "/trust-lists",
        &json!({
            "jurisdiction": "JP",
            "framework": "meti",
            "entries": [{"node": "jp-root", "not_before": t(0)}]
        }),
        None,
    )
    .await;
    assert_eq!(resp.status, 201);
    let doc = json_of(&get(&format!("{base}/trust-lists?jurisdiction={}", enc("JP"))).await);
    assert_eq!(doc["trust_lists"][0]["framework"], "meti");
    assert_eq!(doc["trust_lists"][0]["entries"][0]["node"], "jp-root");

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Master list (M-of-K)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn master_list_m_of_k_shape_and_live_quorum() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let doc = json_of(&get(&format!("{base}/master-list")).await);
    assert_eq!(doc["m_of_k"]["m"], 2);
    assert_eq!(doc["m_of_k"]["k"], 3);
    // Multiple independent log witnesses are listed with their keys.
    let witnesses = doc["witnesses"].as_array().unwrap();
    assert_eq!(witnesses.len(), 3);
    let ids: Vec<&str> = witnesses
        .iter()
        .map(|w| w["node"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"witness-1"));
    assert!(ids.contains(&"witness-3"));
    assert!(witnesses.iter().all(|w| w["suite"] == "ed25519"));
    assert!(witnesses.iter().all(|w| w["public_len"] == 32));

    // The seeded entry for eu-root is quorate with all three
    // attestations verifying live.
    let entries = doc["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["node"], "eu-root");
    assert_eq!(entries[0]["verified_witnesses"], 3);
    assert_eq!(entries[0]["quorate"], true);
    assert_eq!(entries[0]["threshold_required"], 2);
    assert!(entries[0]["attestations"][0]["verified"].as_bool().unwrap());

    // Raise the threshold to a strict majority-of-all (m=3 of k=3):
    // the seeded entry still passes (all three verify), then an entry
    // with only two attestations flips unquorate (live computation,
    // no restart).
    let witnesses_v = doc["witnesses"].clone();
    let resp = post(
        base,
        "/master-list/witnesses",
        &json!({"m": 3, "witnesses": witnesses_v}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201);
    let doc = json_of(&get(&format!("{base}/master-list")).await);
    assert_eq!(doc["m_of_k"]["m"], 3);
    assert_eq!(doc["entries"][0]["verified_witnesses"], 3);
    assert_eq!(doc["entries"][0]["quorate"], true, "3 of 3 verifies");

    // m > k is structurally invalid.
    assert_eq!(
        post(
            base,
            "/master-list/witnesses",
            &json!({"m": 4, "witnesses": witnesses_v}),
            None,
        )
        .await
        .status,
        400
    );

    // Replace the eu-root entry with only two witnesses' attestations:
    // 2 < m=3 → unquorate.
    let w1 = KeyPair::seeded(Suite::Ed25519, b"scenario/w1").unwrap();
    let w2 = KeyPair::seeded(Suite::Ed25519, b"scenario/w2").unwrap();
    let root = NodeId::new("eu-root").unwrap();
    let attestation_v = |witness: &str, key: &KeyPair| -> Value {
        let att = unidpp_signatif::graph::WitnessAttestation::mint_sign(
            &NodeId::new(witness).unwrap(),
            &root,
            t_model(0),
            key,
        )
        .unwrap();
        json!({
            "witness": att.witness.to_string(),
            "at": t(0),
            "slot": {
                "suite": "ed25519",
                "key_id": att.slot.key_id.to_string(),
                "signature": hex_encode(att.slot.signature.as_ref().unwrap()),
            }
        })
    };
    let atts = vec![
        attestation_v("witness-1", &w1),
        attestation_v("witness-2", &w2),
    ];
    let resp = post(
        base,
        "/master-list/entries",
        &json!({"node": root.to_string(), "attestations": atts}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201);
    let doc = json_of(&get(&format!("{base}/master-list")).await);
    assert_eq!(doc["entries"][0]["verified_witnesses"], 2);
    assert_eq!(doc["entries"][0]["quorate"], false, "2 verified < m=3");

    // An attestation by an unknown witness is rejected on input.
    let bad = json!({
        "node": "eu-notified",
        "attestations": [{"witness": "ghost", "at": t(0), "slot": {
            "suite": "ed25519", "key_id": "k-0000000000000000",
            "signature": "00".repeat(64)
        }}]
    });
    assert_eq!(
        post(base, "/master-list/entries", &bad, None).await.status,
        400
    );

    // A real witness attesting another node is accepted and verifies
    // (still under m=3: one witness is not quorate).
    let w1b = KeyPair::seeded(Suite::Ed25519, b"scenario/w1").unwrap();
    let node = NodeId::new("eu-notified").unwrap();
    let att = unidpp_signatif::graph::WitnessAttestation::mint_sign(
        &NodeId::new("witness-1").unwrap(),
        &node,
        t_model(0),
        &w1b,
    )
    .unwrap();
    let entry_v = json!({
        "node": node.to_string(),
        "attestations": [{"witness": "witness-1", "at": t(0), "slot": {
            "suite": "ed25519",
            "key_id": att.slot.key_id.to_string(),
            "signature": hex_encode(att.slot.signature.as_ref().unwrap()),
        }}]
    });
    let resp = post(base, "/master-list/entries", &entry_v, None).await;
    assert_eq!(resp.status, 201);
    let doc = json_of(&get(&format!("{base}/master-list")).await);
    let e = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["node"] == "eu-notified")
        .unwrap();
    assert_eq!(e["verified_witnesses"], 1);
    assert_eq!(e["quorate"], false, "1 verified witness < m=3");

    // Bad witness-set validation.
    assert_eq!(
        post(
            base,
            "/master-list/witnesses",
            &json!({"m": 0, "witnesses": witnesses_v}),
            None
        )
        .await
        .status,
        400
    );
    assert_eq!(
        post(
            base,
            "/master-list/witnesses",
            &json!({"m": 9, "witnesses": witnesses_v}),
            None
        )
        .await
        .status,
        400
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Revocations: live reason → retroactivity semantics
// ---------------------------------------------------------------------------

/// Fetch revocations rendered with `at` / `known_by` and return the
/// per-declaration views.
async fn revocations_at(base: &str, at: &str, known_by: Option<&str>) -> Vec<Value> {
    let mut url = format!("{base}/revocations?at={}", enc(at));
    if let Some(kb) = known_by {
        url.push_str(&format!("&known_by={}", enc(kb)));
    }
    let doc = json_of(&get(&url).await);
    doc["revocations"].as_array().unwrap().clone()
}

#[tokio::test]
async fn retroactive_window_voids_ab_initio_and_revalidates_outside() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // The seeded misissuance window is [T0+3000, T0+8000], declared
    // at T0+10000.
    let views = revocations_at(base, &t(5_000), None).await;
    let mis = views
        .iter()
        .find(|v| v["reason"]["token"] == "misissuance")
        .expect("seeded misissuance");
    assert_eq!(mis["reason"]["retroactive"], true);
    assert_eq!(mis["window"]["start"], t(3_000));
    assert_eq!(mis["window"]["end"], t(8_000));
    assert_eq!(mis["window"]["open"], false);
    assert_eq!(mis["declared_at"], t(10_000));
    assert_eq!(mis["voids_at_as_of"], true);
    assert_eq!(mis["standing_at_as_of"], "void-ab-initio");
    assert_eq!(mis["verifications_at_stand"], false);
    assert_eq!(mis["quorum"]["quorate"], true);
    assert_eq!(mis["quorum"]["threshold"], 2);
    assert_eq!(mis["quorum"]["verified_count"], 3);

    // Before the window: re-validated (void ab initio does not leak
    // past the window start).
    let views = revocations_at(base, &t(2_500), None).await;
    let mis = views
        .iter()
        .find(|v| v["reason"]["token"] == "misissuance")
        .unwrap();
    assert_eq!(mis["voids_at_as_of"], false);
    assert_eq!(mis["standing_at_as_of"], "valid");
    assert_eq!(mis["verifications_at_stand"], true);

    // After the window: re-validated.
    let views = revocations_at(base, &t(9_000), None).await;
    let mis = views
        .iter()
        .find(|v| v["reason"]["token"] == "misissuance")
        .unwrap();
    assert_eq!(mis["voids_at_as_of"], false);
    assert_eq!(mis["standing_at_as_of"], "valid");

    // Window endpoints are inclusive (Interval::contains).
    let views = revocations_at(base, &t(3_000), None).await;
    let mis = views
        .iter()
        .find(|v| v["reason"]["token"] == "misissuance")
        .unwrap();
    assert_eq!(mis["voids_at_as_of"], true);

    server.stop().await;
}

#[tokio::test]
async fn evidentiary_cutoff_keeps_pre_declaration_verifications_valid() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // A diligent verifier evaluated acts at T0+5000 before the
    // declaration became knowable (declared at T0+10000): the
    // retroactive declaration is not yet known, so its verification
    // stands — the evidentiary reading.
    let views = revocations_at(base, &t(5_000), Some(&t(9_999))).await;
    let mis = views
        .iter()
        .find(|v| v["reason"]["token"] == "misissuance")
        .unwrap();
    assert_eq!(mis["known_at_cutoff"], false);
    assert_eq!(mis["voids_at_as_of"], false);
    assert_eq!(mis["verifications_at_stand"], true);

    // One second later the declaration is knowable: void ab initio —
    // timestamping does NOT protect against retroactive reasons.
    let views = revocations_at(base, &t(5_000), Some(&t(10_000))).await;
    let mis = views
        .iter()
        .find(|v| v["reason"]["token"] == "misissuance")
        .unwrap();
    assert_eq!(mis["known_at_cutoff"], true);
    assert_eq!(mis["voids_at_as_of"], true);
    assert_eq!(mis["standing_at_as_of"], "void-ab-initio");

    server.stop().await;
}

#[tokio::test]
async fn prospective_reason_keeps_prior_as_of_verifications_valid() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // The seeded key-compromise: effect from T0+9500, declared at
    // T0+10500.
    let views = revocations_at(base, &t(9_000), None).await;
    let kc = views
        .iter()
        .find(|v| v["reason"]["token"] == "key-compromise")
        .unwrap();
    assert_eq!(kc["reason"]["retroactive"], false);
    assert_eq!(kc["reason"]["after"], t(9_500));
    assert_eq!(kc["window"]["open"], true);
    // Acts before the compromise moment stand.
    assert_eq!(kc["voids_at_as_of"], false);
    assert_eq!(kc["verifications_at_stand"], true);

    // From the effect moment onward: suspended (not void).
    let views = revocations_at(base, &t(9_900), None).await;
    let kc = views
        .iter()
        .find(|v| v["reason"]["token"] == "key-compromise")
        .unwrap();
    assert_eq!(kc["voids_at_as_of"], true);
    assert_eq!(kc["standing_at_as_of"], "suspended-from");
    assert_eq!(kc["verifications_at_stand"], false);

    // A verification made before the effect moment remains valid even
    // after the declaration (prospective: timestamping protects).
    let views = revocations_at(base, &t(9_000), Some(&t(11_000))).await;
    let kc = views
        .iter()
        .find(|v| v["reason"]["token"] == "key-compromise")
        .unwrap();
    assert_eq!(kc["known_at_cutoff"], true);
    assert_eq!(kc["voids_at_as_of"], false, "act predates the compromise");

    server.stop().await;
}

#[tokio::test]
async fn revocation_filters_and_validation() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // Subject filter (the seeded issuer key id).
    let issuer_id = issuer_key().key_id().to_string();
    let label = format!("key:{}", issuer_id);
    let url = format!(
        "{base}/revocations?subject={}&at={}",
        enc(&label),
        enc(&t(5_000))
    );
    let doc = json_of(&get(&url).await);
    assert_eq!(
        doc["count"], 2,
        "both seeded declarations are on the issuer key"
    );
    assert_eq!(doc["query"]["subject"], label);

    // Retroactivity filter.
    let doc = json_of(
        &get(&format!(
            "{base}/revocations?retroactive=true&at={}",
            enc(&t(5_000))
        ))
        .await,
    );
    assert_eq!(doc["count"], 1);
    assert_eq!(doc["revocations"][0]["reason"]["token"], "misissuance");
    let doc = json_of(
        &get(&format!(
            "{base}/revocations?retroactive=false&at={}",
            enc(&t(5_000))
        ))
        .await,
    );
    assert_eq!(doc["revocations"][0]["reason"]["token"], "key-compromise");

    // Window filter: declarations whose distrust window intersects
    // [start, end].
    let doc = json_of(
        &get(&format!(
            "{base}/revocations?window={}&at={}",
            enc(&format!("{}..{}", t(3_500), t(4_000))),
            enc(&t(5_000))
        ))
        .await,
    );
    assert_eq!(doc["count"], 1, "only the misissuance window intersects");

    // Bad parameters are rejected.
    assert_eq!(
        get(&format!("{base}/revocations?window=abc&at={}", enc(&t(0))))
            .await
            .status,
        400
    );
    assert_eq!(
        get(&format!("{base}/revocations?at=nonsense")).await.status,
        400
    );
    assert_eq!(
        get(&format!(
            "{base}/revocations?known_by=zzz&at={}",
            enc(&t(0))
        ))
        .await
        .status,
        400
    );

    // Declaration validation: retroactive without a quorum is refused
    // (authority-over-authority is a threshold decision).
    let no_quorum = json!({
        "subject": {"kind": "key", "id": issuer_id},
        "reason": {"token": "fraudulent-issuance"},
        "declared_at": t(12_000),
        "window": {"start": t(11_000), "end": t(12_000)},
        "declared_by": "eu-super-quorum",
    });
    let resp = post(base, "/revocations", &no_quorum, None).await;
    assert_eq!(resp.status, 422);
    assert!(json_of(&resp)["error"].as_str().unwrap().contains("quorum"));

    // A below-threshold quorum is refused too.
    let members = quorum_members();
    let solo_refs: Vec<&KeyPair> = members[..1].iter().collect::<Vec<_>>();
    let mut rev = Revocation {
        subject: RevokedSubject::Key(KeyId::new(&issuer_id).unwrap()),
        reason: RevocationReason::Misissuance,
        declared_at: t_model(12_000),
        window: Interval::between(t_model(11_000), t_model(12_000)).unwrap(),
        declared_by: NodeId::new("eu-super-quorum").unwrap(),
        quorum: None,
    };
    let att = QuorumAttestation::mint_sign(&rev.declared_by, 2, &rev.statement_bytes(), &solo_refs)
        .unwrap();
    rev.quorum = Some(att);
    let below = revocation_to_value(&rev);
    assert_eq!(post(base, "/revocations", &below, None).await.status, 422);

    // A quorate declaration lands and shows up live.
    let members = quorum_members();
    let refs: Vec<&KeyPair> = members.iter().collect();
    let mut rev = Revocation {
        subject: RevokedSubject::Key(KeyId::new(&issuer_id).unwrap()),
        reason: RevocationReason::FraudulentIssuance,
        declared_at: t_model(12_000),
        window: Interval::between(t_model(6_000), t_model(7_000)).unwrap(),
        declared_by: NodeId::new("eu-super-quorum").unwrap(),
        quorum: None,
    };
    let att =
        QuorumAttestation::mint_sign(&rev.declared_by, 2, &rev.statement_bytes(), &refs).unwrap();
    rev.quorum = Some(att);
    let resp = post(base, "/revocations", &revocation_to_value(&rev), None).await;
    assert_eq!(resp.status, 201);
    // Live: the new declaration voids acts at T0+6500.
    let views = revocations_at(base, &t(6_500), None).await;
    let fraud = views
        .iter()
        .find(|v| v["reason"]["token"] == "fraudulent-issuance")
        .expect("new declaration visible");
    assert_eq!(fraud["voids_at_as_of"], true);
    assert_eq!(fraud["standing_at_as_of"], "void-ab-initio");

    // A prospective declaration needs no quorum.
    let pros = json!({
        "subject": {"kind": "node", "id": "eu-notified"},
        "reason": {"token": "cessation"},
        "declared_at": t(13_000),
        "window": {"start": t(13_000)},
        "declared_by": "eu-root",
    });
    assert_eq!(post(base, "/revocations", &pros, None).await.status, 201);

    // Bad reason token / inverted window / bad subject.
    let mut bad = pros.clone();
    bad["reason"] = json!({"token": "made-up"});
    assert_eq!(post(base, "/revocations", &bad, None).await.status, 400);
    let mut bad = pros.clone();
    bad["reason"] = json!({"token": "key-compromise"});
    assert_eq!(
        post(base, "/revocations", &bad, None).await.status,
        400,
        "key-compromise requires `after`"
    );
    let mut bad = pros.clone();
    bad["window"] = json!({"start": t(14_000), "end": t(13_000)});
    assert_eq!(post(base, "/revocations", &bad, None).await.status, 400);
    let mut bad = pros.clone();
    bad["subject"] = json!({"kind": "wat", "id": "x"});
    assert_eq!(post(base, "/revocations", &bad, None).await.status, 400);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Admin auth + audit log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_auth_and_audit_log() {
    let server = TestServer::spawn(Config {
        admin_token: Some("s3cret".to_string()),
        ..Config::default()
    })
    .await
    .expect("spawn server");
    let base = &server.base_url;

    // Reads stay public; mutations are guarded.
    assert_eq!(get(&format!("{base}/trust-lists")).await.status, 200);
    let body = json!({"jurisdiction": "DE"});
    assert_eq!(post(base, "/trust-lists", &body, None).await.status, 401);
    assert_eq!(
        post(base, "/trust-lists", &body, Some("wrong"))
            .await
            .status,
        401
    );
    assert_eq!(
        post(base, "/trust-lists", &body, Some("s3cret"))
            .await
            .status,
        201
    );

    // The audit log is admin-only and records every mutation.
    assert_eq!(get(&format!("{base}/admin/log")).await.status, 401);
    let resp = json_request("GET", &format!("{base}/admin/log"), None, Some("s3cret")).await;
    assert_eq!(resp.status, 200);
    let log = json_of(&resp);
    // 18 seed ops (10 nodes, 2 edges, 1 list, 1 entry, 1 witness set,
    // 1 master entry, 2 revocations) + the mutation above.
    assert_eq!(log["total"], 19);
    // The record of the mutation is the last one, with a monotonic seq.
    let records = log["records"].as_array().unwrap();
    let last = records.last().unwrap();
    assert_eq!(last["op"], "register-trust-list");
    assert_eq!(last["body"]["jurisdiction"], "DE");

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Journal persistence across restarts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn journal_replays_state_across_restart() {
    let dir = std::env::temp_dir().join(format!("unidpp-trust-it-{}", std::process::id()));
    let path = dir.join("trust.jsonl");
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir_all(&dir).unwrap();
    let config = Config {
        state_file: Some(path.clone()),
        ..Config::default()
    };

    let seed_log_total;
    {
        let server = TestServer::spawn(config.clone()).await.expect("spawn A");
        let base = &server.base_url;
        // Seeded state visible.
        let doc = json_of(&get(&format!("{base}/trust-lists")).await);
        assert_eq!(doc["count"], 1);
        // Mutate: withdraw the root as of T0+20000 and declare a
        // prospective revocation.
        assert_eq!(
            post(
                base,
                "/trust-lists/EU/entries",
                &json!({"node": "eu-root", "not_before": t(0), "superseded_at": t(20_000)}),
                None
            )
            .await
            .status,
            201
        );
        assert_eq!(
            post(
                base,
                "/revocations",
                &json!({
                    "subject": {"kind": "node", "id": "eu-notified"},
                    "reason": {"token": "cessation"},
                    "declared_at": t(15_000),
                    "window": {"start": t(15_000)},
                    "declared_by": "eu-root",
                }),
                None
            )
            .await
            .status,
            201
        );
        seed_log_total = json_of(&get(&format!("{base}/admin/log")).await)["total"]
            .as_u64()
            .unwrap();
        server.stop().await;
    }

    // A fresh server on the same journal replays seed + mutations.
    let server = TestServer::spawn(config).await.expect("spawn B");
    let base = &server.base_url;
    let doc = json_of(&get(&format!("{base}/trust-lists/EU?at={}", enc(&t(25_000)))).await);
    assert_eq!(
        doc["entries"][0]["in_force_at_as_of"], false,
        "withdrawal survives restart"
    );
    let doc = json_of(&get(&format!("{base}/revocations?at={}", enc(&t(16_000)))).await);
    assert_eq!(doc["count"], 3, "2 seeded + 1 journaled declaration");
    let log = json_of(&get(&format!("{base}/admin/log")).await);
    assert_eq!(log["total"].as_u64().unwrap(), seed_log_total);
    // The seeded graph survived too.
    let doc = json_of(&get(&format!("{base}/graph")).await);
    assert!(doc["node_count"].as_u64().unwrap() > 5);
    server.stop().await;

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// The flagship: a verdict verifier fetches live state and resolves
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verifier_fetches_live_state_and_resolves_trust_path() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // 1. Fetch the graph and reconstruct the signatif TrustGraph.
    let doc = json_of(&get(&format!("{base}/graph")).await);
    let mut graph = TrustGraph::new();
    for n in doc["nodes"].as_array().unwrap() {
        graph.add_node(node_from_value(n).expect("node wire"));
    }
    for e in doc["edges"].as_array().unwrap() {
        graph
            .add_edge(edge_from_value(e).expect("edge wire"))
            .expect("edge verifies");
    }
    assert_eq!(
        graph.node_count() as u64,
        doc["node_count"].as_u64().unwrap()
    );
    assert_eq!(
        graph.edge_count() as u64,
        doc["edge_count"].as_u64().unwrap()
    );

    // 2. Fetch the anchor bundle and reconstruct the AnchorBundle.
    let b = json_of(&get(&format!("{base}/anchor-bundle?jurisdiction={}", enc("EU"))).await);
    assert_eq!(b["jurisdiction"], "EU");
    let mut list = TrustList::new("EU");
    for e in b["trust_lists"][0]["entries"].as_array().unwrap() {
        let node = NodeId::new(e["node"].as_str().unwrap()).unwrap();
        let not_before = unidpp_model::Timestamp::parse(e["not_before"].as_str().unwrap()).unwrap();
        list.trust(node, not_before);
    }
    let mut witnesses = BTreeMap::new();
    for w in b["master"]["witnesses"].as_array().unwrap() {
        let node = NodeId::new(w["node"].as_str().unwrap()).unwrap();
        let bytes = hex_decode(w["public"].as_str().unwrap()).unwrap();
        witnesses.insert(node, PublicKey::from_bytes(&bytes).unwrap());
    }
    let mut master = MasterList::new(b["master"]["m"].as_u64().unwrap() as usize, witnesses);
    for e in b["master"]["entries"].as_array().unwrap() {
        let node = NodeId::new(e["node"].as_str().unwrap()).unwrap();
        let attestations = e["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| witness_attestation_from_value(a).expect("attestation wire"))
            .collect();
        master.upsert(MasterListEntry { node, attestations });
    }
    let bundle = AnchorBundle {
        jurisdiction: "EU".into(),
        trust_lists: vec![list],
        master,
    };

    // 3. Resolve the seeded issuer key exactly as signatif's own
    //    graph test does — live state, fetched over HTTP.
    let key = issuer_key();
    let req = ScopeRequest::new(
        "eu",
        "urn:unidpp:profile:eu-batt@3",
        "batteries",
        t_model(6_000),
    );
    let path = graph
        .resolve(key.key_id(), &req, &bundle)
        .expect("live trust path resolves");
    assert_eq!(path.root, NodeId::new("eu-root").unwrap());
    assert_eq!(path.end, NodeId::new("issuer-key-a").unwrap());
    assert_eq!(path.hops(), 2);
    assert!(path.effective_scope.matches(&req));

    // Out-of-scope product group: the same exclusion signatif's test
    // produces.
    let outside = ScopeRequest::new(
        "eu",
        "urn:unidpp:profile:eu-batt@3",
        "textiles",
        t_model(6_000),
    );
    assert!(matches!(
        graph.resolve(key.key_id(), &outside, &bundle),
        Err(unidpp_signatif::SignatifError::ScopeExcluded { .. })
    ));

    // The multi-suite co-signature discipline: the issuer node's
    // second (P-256) key also resolves.
    let alt = KeyPair::seeded(Suite::EcdsaP256, b"scenario/issuer-a-alt").unwrap();
    assert!(graph.resolve(alt.key_id(), &req, &bundle).is_ok());

    // The anchor bundle requires the jurisdiction parameter.
    assert_eq!(get(&format!("{base}/anchor-bundle")).await.status, 400);
    assert_eq!(
        get(&format!("{base}/anchor-bundle?jurisdiction={}", enc("XX")))
            .await
            .status,
        404
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Nodes and edges administration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn node_and_edge_administration() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // Register a new delegated node under the seeded root.
    let new_key = KeyPair::seeded(Suite::Ed25519, b"admin/new-node").unwrap();
    let node = json!({
        "id": "new-authority",
        "kind": "delegated",
        "keys": [{
            "key_id": new_key.key_id().to_string(),
            "suite": "ed25519",
            "public": hex_encode(new_key.public().as_bytes()),
        }]
    });
    assert_eq!(post(base, "/nodes", &node, None).await.status, 201);

    // A key id that does not match the declared public key is rejected.
    let mut bad = node.clone();
    bad["keys"][0]["key_id"] = json!("k-0000000000000000");
    assert_eq!(post(base, "/nodes", &bad, None).await.status, 400);

    // Edge from the root, signed by the root key (seeded).
    let root_key = KeyPair::seeded(Suite::Ed25519, b"scenario/eu-root").unwrap();
    let cred = unidpp_signatif::graph::DelegationCredential::mint_sign(
        &NodeId::new("eu-root").unwrap(),
        &NodeId::new("new-authority").unwrap(),
        unidpp_signatif::scope::DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"]),
        &root_key,
    )
    .unwrap();
    let edge_v = unidpp_trust::wire::edge_to_value(&cred);
    assert_eq!(post(base, "/edges", &edge_v, None).await.status, 201);

    // An edge to an unknown node is rejected.
    let mut ghost = edge_v.clone();
    ghost["child"] = json!("ghost");
    assert_eq!(post(base, "/edges", &ghost, None).await.status, 400);

    // The graph grew.
    let doc = json_of(&get(&format!("{base}/graph")).await);
    assert_eq!(doc["edge_count"], 3);
    assert!(doc["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["id"] == "new-authority"));

    server.stop().await;
}
