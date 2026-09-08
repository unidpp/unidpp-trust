//! Integration: the threshold ceremony meets the trust service.
//!
//! SIGNATIF's `RealCeremony` (Feldman VSS + threshold Schnorr partials
//! combining into one standard Ed25519 group signature) has never been
//! driven through this service's revocation intake. This test closes
//! that loop end to end over real HTTP:
//!
//! 1. a 2-of-3 multi-jurisdiction quorum runs a **Sign ceremony** over
//!    a retroactive revocation statement's canonical bytes;
//! 2. a below-threshold qualifying set is refused by the ceremony
//!    itself (`ThresholdNotMet` — the refusal is the cryptography);
//! 3. the quorate group signature is posted as the revocation's quorum
//!    attestation — **before** the quorum node pins the group key
//!    (422: pinning is load-bearing), then after (201);
//! 4. the declaration's retroactivity is visible in the standing the
//!    service serves: void ab initio inside the window, re-validated
//!    outside it, unknown before the evidentiary cutoff;
//! 5. the `GET /revocations` quorum view names the threshold-group
//!    form and its verdict.

mod support;

use serde_json::{json, Value};
use support::{enc, get, json_of};
use unidpp_model::Interval;
use unidpp_signatif::confium::real::RealCeremony;
use unidpp_signatif::confium::{
    CeremonyCoordinator, CeremonyError, CeremonyKind, CeremonyStatement, QuorumSpec, SessionInit,
};
use unidpp_signatif::graph::NodeId;
use unidpp_signatif::keyring::KeyId;
use unidpp_signatif::revoke::{QuorumAttestation, Revocation, RevocationReason, RevokedSubject};
use unidpp_trust::wire::{node_to_value, revocation_to_value};
use unidpp_trust::{Config, TestServer, Timestamp};

/// The multi-jurisdiction regulator quorum (the demo's cast): three
/// member authorities, two of which must act together.
const QUORUM_ID: &str = "e8-retro-quorum";
const QUORUM_THRESHOLD: usize = 2;
const MEMBERS: [&str; 3] = ["reg-cn-samr", "reg-jp-meti", "reg-eu-espr"];
/// The qualifying set: two members from two different jurisdictions.
const QUALIFYING: [&str; 2] = ["reg-cn-samr", "reg-jp-meti"];
/// The distrusted issuing authority (its lot passports are the story's
/// recalled cells).
const SUBJECT_NODE: &str = "haichuan-cn";

fn t(secs: i64) -> String {
    Timestamp::from_secs(secs).to_string()
}

fn quorum_spec() -> QuorumSpec {
    QuorumSpec {
        quorum_id: NodeId::new(QUORUM_ID).unwrap(),
        threshold: QUORUM_THRESHOLD,
        members: MEMBERS.map(|m| NodeId::new(m).unwrap()).to_vec(),
    }
}

/// The retroactive declaration the quorum is being asked to authorize.
fn revocation() -> Revocation {
    Revocation {
        subject: RevokedSubject::Node(NodeId::new(SUBJECT_NODE).unwrap()),
        reason: RevocationReason::Misissuance,
        // 2030-06-15T00:00:00Z (after the B9 recall of 2030-05).
        declared_at: unidpp_model::Timestamp::from_secs(1_872_499_200),
        // 2027-01-01 .. 2030-06-01: everything the authority issued in
        // the window is void ab initio.
        window: Interval::between(
            unidpp_model::Timestamp::from_secs(1_792_876_800),
            unidpp_model::Timestamp::from_secs(1_871_596_800),
        )
        .unwrap(),
        declared_by: NodeId::new(QUORUM_ID).unwrap(),
        quorum: None,
    }
}

/// Run a real Sign ceremony over the attestation's canonical bytes with
/// `signers` as the qualifying set. Below-threshold sets fail the
/// ceremony's own aggregate step.
fn run_ceremony(
    rev: &Revocation,
    signers: &[&str],
) -> Result<
    (
        QuorumAttestation,
        unidpp_signatif::confium::AggregatedSignature,
        unidpp_signatif::threshold::GroupKey,
    ),
    CeremonyError,
> {
    let payload = QuorumAttestation::canonical_bytes(
        &rev.statement_bytes(),
        &NodeId::new(QUORUM_ID).unwrap(),
        QUORUM_THRESHOLD,
    );
    let mut ceremony = RealCeremony::new(None);
    let session = ceremony.create_session(SessionInit {
        kind: CeremonyKind::Sign,
        statement: CeremonyStatement {
            label: format!("retroactive-distrust:{}", rev.subject.label()),
            payload,
        },
        quorum: quorum_spec(),
        expires_at: None,
    })?;
    let signer_ids: Vec<NodeId> = signers.iter().map(|s| NodeId::new(s).unwrap()).collect();
    for signer in &signer_ids {
        let commitment = ceremony.commitment_for(&session, signer)?;
        ceremony.submit_commitment(&session, commitment)?;
    }
    // Below the threshold, round 1 never closes — the refusal the
    // below-threshold path asserts arrives at aggregate time, which is
    // where the seam states it (strict rounds; ThresholdNotMet is the
    // threshold's own voice, not a round-ordering accident).
    if signer_ids.len() < quorum_spec().threshold {
        return Err(ceremony.aggregate(&session).unwrap_err());
    }
    for signer in &signer_ids {
        let share = ceremony.share_for(&session, signer)?;
        ceremony.submit_share(&session, share)?;
    }
    let aggregated = ceremony.aggregate(&session)?;
    let group = ceremony.group(&session)?;
    Ok((
        QuorumAttestation {
            quorum: NodeId::new(QUORUM_ID).unwrap(),
            threshold: QUORUM_THRESHOLD,
            signatures: vec![aggregated.to_slot()],
        },
        aggregated,
        group,
    ))
}

async fn post(base: &str, path: &str, body: &Value) -> support::HttpResponse {
    support::json_request(
        "POST",
        &format!("{base}{path}"),
        Some(&body.to_string()),
        None,
    )
    .await
}

/// The quorum node body: the threshold group pinning the ceremony's
/// group public key as its registered key.
fn quorum_node_body(group_public: &unidpp_signatif::keyring::PublicKey) -> Value {
    let mut node = unidpp_signatif::graph::DelegationNode::new(
        NodeId::new(QUORUM_ID).unwrap(),
        unidpp_signatif::graph::NodeKind::ThresholdGroup {
            threshold: QUORUM_THRESHOLD,
            members: MEMBERS
                .iter()
                .map(|m| NodeId::new(m).unwrap())
                .collect::<std::collections::BTreeSet<_>>(),
        },
    );
    node.register(unidpp_signatif::graph::RegisteredKey {
        key_id: KeyId::of(group_public),
        public: *group_public,
    });
    node_to_value(&node)
}

async fn revocations_at(base: &str, at: &str, known_by: Option<&str>) -> Vec<Value> {
    let mut url = format!("{base}/revocations?at={}", enc(at));
    if let Some(kb) = known_by {
        url.push_str(&format!("&known_by={}", enc(kb)));
    }
    json_of(&get(&url).await)["revocations"]
        .as_array()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn quorate_ceremony_drives_retroactive_revocation_over_http() {
    let server = TestServer::spawn(Config {
        seed_fixtures: false,
        ..Config::default()
    })
    .await
    .expect("spawn server");
    let base = &server.base_url;
    let rev = revocation();

    // -- 1. Below the threshold the ceremony itself refuses: one
    //       regulator alone cannot produce a group signature. --
    let below = run_ceremony(&rev, &["reg-cn-samr"]).unwrap_err();
    assert!(
        matches!(below, CeremonyError::ThresholdNotMet { need: 2, .. }),
        "one member alone must not reach the ceremony: {below:?}"
    );

    // And the service refuses the retroactive declaration with no
    // attestation at all (authority-over-authority is a threshold
    // decision).
    let mut body = revocation_to_value(&rev);
    body["quorum"] = Value::Null;
    let resp = post(base, "/revocations", &body).await;
    assert_eq!(resp.status, 422);
    assert!(json_of(&resp)["error"]
        .as_str()
        .unwrap()
        .contains("requires a quorum attestation"));

    // -- 2. The quorate ceremony: two members from two different
    //       jurisdictions combine partials into one group signature. --
    let (attestation, aggregated, group) =
        run_ceremony(&rev, &QUALIFYING).expect("quorate ceremony");
    // The ceremony's own check: a standard Ed25519 signature under the
    // group key over the Quorum-domain-framed canonical bytes.
    aggregated
        .verify(&CeremonyStatement {
            label: String::new(),
            payload: QuorumAttestation::canonical_bytes(
                &rev.statement_bytes(),
                &NodeId::new(QUORUM_ID).unwrap(),
                QUORUM_THRESHOLD,
            ),
        })
        .expect("group signature verifies");
    // No member key exists: the group key matches no member (it is the
    // polynomial's constant term; members hold evaluations).
    let mut rev = rev;
    rev.quorum = Some(attestation);
    let body = revocation_to_value(&rev);

    // -- 3. Pinning is load-bearing: before the quorum node registers
    //       the group key, the attestation certifies nothing (422). --
    let resp = post(base, "/revocations", &body).await;
    assert_eq!(resp.status, 422);
    let err = json_of(&resp)["error"].as_str().unwrap().to_string();
    assert!(
        err.contains("does not reach the threshold"),
        "unpinned group key must not certify: {err}"
    );

    // Pin the group key on the quorum node.
    let node_body = quorum_node_body(&aggregated.group_key);
    assert_eq!(node_body["keys"][0]["public"], json!(group.group_public));
    assert_eq!(node_body["keys"][0]["public_len"], 32);
    let resp = post(base, "/nodes", &node_body).await;
    assert_eq!(resp.status, 201);

    // -- 4. Quorate: the same declaration is accepted (201). --
    let resp = post(base, "/revocations", &body).await;
    assert_eq!(resp.status, 201, "body: {}", resp.body_string());
    let created = json_of(&resp);
    assert_eq!(created["subject"]["id"], SUBJECT_NODE);
    assert_eq!(created["reason"]["token"], "misissuance");
    assert_eq!(created["reason"]["retroactive"], true);

    // -- 5. Retroactivity is visible in the standing the service
    //       serves. Inside the window: void ab initio. --
    let views = revocations_at(base, &t(1_838_464_000), None).await; // 2028-02-15
    assert_eq!(views.len(), 1);
    let v = &views[0];
    assert_eq!(v["standing_at_as_of"], "void-ab-initio");
    assert_eq!(v["voids_at_as_of"], true);
    assert_eq!(v["verifications_at_stand"], false);
    let q = &v["quorum"];
    assert_eq!(q["quorum"], QUORUM_ID);
    assert_eq!(q["threshold"], QUORUM_THRESHOLD);
    assert_eq!(q["form"], "threshold-group");
    assert_eq!(q["group_verified"], true);
    assert_eq!(q["quorate"], true);
    assert_eq!(
        q["verified_count"], 0,
        "the group key is not a member key — the slot count is not the threshold"
    );

    // Before the window: re-validated (a retroactive window does not
    // leak past its start).
    let views = revocations_at(base, &t(1_783_008_000), None).await; // 2026-07-01
    assert_eq!(views[0]["standing_at_as_of"], "valid");
    assert_eq!(views[0]["voids_at_as_of"], false);

    // After the window end: re-validated.
    let views = revocations_at(base, &t(1_872_499_199), None).await; // 2030-06-14T23:59:59Z
    assert_eq!(views[0]["standing_at_as_of"], "valid");

    // Evidentiary cutoff: before the declaration was knowable, a
    // diligent verifier's as-of-in-window verification stands.
    let views = revocations_at(base, &t(1_838_464_000), Some(&t(1_872_499_199))).await;
    assert_eq!(views[0]["known_at_cutoff"], false);
    assert_eq!(views[0]["verifications_at_stand"], true);
    let views = revocations_at(base, &t(1_838_464_000), Some(&t(1_872_499_200))).await;
    assert_eq!(views[0]["known_at_cutoff"], true);
    assert_eq!(views[0]["standing_at_as_of"], "void-ab-initio");

    // The subject filter finds it by label.
    let doc = json_of(
        &get(&format!(
            "{base}/revocations?subject={}&at={}",
            enc(&format!("node:{SUBJECT_NODE}")),
            enc(&t(1_838_464_000))
        ))
        .await,
    );
    assert_eq!(doc["count"], 1);

    // The graph serves the pinned group key (verifiers reconstruct the
    // quorum node exactly as the ceremony published it).
    let doc = json_of(&get(&format!("{base}/graph")).await);
    let quorum_node = doc["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == QUORUM_ID)
        .expect("quorum node in the graph");
    assert_eq!(
        quorum_node["kind"]["threshold_group"]["threshold"],
        QUORUM_THRESHOLD
    );
    assert_eq!(
        quorum_node["kind"]["threshold_group"]["members"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(quorum_node["keys"][0]["public"], group.group_public);

    server.stop().await;
}

#[tokio::test]
async fn group_form_survives_journal_replay() {
    // The declare op's quorum verification runs again on replay; the
    // ceremony-form declaration must re-certify from the journal alone.
    let dir = std::env::temp_dir().join(format!("unidpp-trust-quorum-{}", std::process::id()));
    let path = dir.join("trust.jsonl");
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir_all(&dir).unwrap();
    let config = Config {
        state_file: Some(path.clone()),
        seed_fixtures: false,
        ..Config::default()
    };

    let rev = revocation();
    let (attestation, aggregated, _group) =
        run_ceremony(&rev, &QUALIFYING).expect("quorate ceremony");
    let mut rev = rev;
    rev.quorum = Some(attestation);
    let node_body = quorum_node_body(&aggregated.group_key);

    {
        let server = TestServer::spawn(config.clone()).await.expect("spawn A");
        assert_eq!(
            post(&server.base_url, "/nodes", &node_body).await.status,
            201
        );
        assert_eq!(
            post(&server.base_url, "/revocations", &revocation_to_value(&rev))
                .await
                .status,
            201
        );
        server.stop().await;
    }
    {
        let server = TestServer::spawn(config).await.expect("spawn B");
        let views = revocations_at(&server.base_url, &t(1_838_464_000), None).await;
        assert_eq!(views.len(), 1, "the declaration replays");
        assert_eq!(views[0]["standing_at_as_of"], "void-ab-initio");
        assert_eq!(views[0]["quorum"]["form"], "threshold-group");
        assert_eq!(views[0]["quorum"]["quorate"], true);
        server.stop().await;
    }
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn tampered_or_mismatched_group_attestations_are_refused() {
    let server = TestServer::spawn(Config {
        seed_fixtures: false,
        ..Config::default()
    })
    .await
    .expect("spawn server");
    let base = &server.base_url;
    let rev = revocation();
    let (attestation, aggregated, _group) =
        run_ceremony(&rev, &QUALIFYING).expect("quorate ceremony");
    let mut rev = rev;
    rev.quorum = Some(attestation);
    let node_body = quorum_node_body(&aggregated.group_key);
    assert_eq!(post(base, "/nodes", &node_body).await.status, 201);

    // A tampered group signature (one flipped byte) must not certify.
    let mut tampered = revocation_to_value(&rev);
    {
        let sig_hex = tampered["quorum"]["signatures"][0]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let mut decoded = Vec::with_capacity(sig_hex.len() / 2);
        for pair in sig_hex.as_bytes().chunks(2) {
            decoded.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
        }
        decoded[10] ^= 0x01;
        let mut flipped = String::with_capacity(decoded.len() * 2);
        for b in decoded {
            flipped.push_str(&format!("{b:02x}"));
        }
        tampered["quorum"]["signatures"][0]["signature"] = json!(flipped);
    }
    let resp = post(base, "/revocations", &tampered).await;
    assert_eq!(resp.status, 422, "tampered group signature refused");

    // A threshold disagreement between the attestation and the pinned
    // quorum node: re-pin the node with threshold 3 and re-declare with
    // the (2-of-3) attestation — refused.
    let mut node3 = node_body.clone();
    node3["kind"]["threshold_group"]["threshold"] = json!(3);
    assert_eq!(post(base, "/nodes", &node3).await.status, 201);
    let resp = post(base, "/revocations", &revocation_to_value(&rev)).await;
    assert_eq!(resp.status, 422, "claimed 2, graph asserts 3");

    // Restoring the agreeing threshold re-accepts the same attestation.
    assert_eq!(post(base, "/nodes", &node_body).await.status, 201);
    let resp = post(base, "/revocations", &revocation_to_value(&rev)).await;
    assert_eq!(resp.status, 201);

    server.stop().await;
}
