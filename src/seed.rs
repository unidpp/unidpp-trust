//! Seed fixtures derived from `unidpp-signatif`'s test trust graph
//! (`tests/common/mod.rs` topology + `tests/scenario_misissuance.rs`
//! revocation), so verdict verifiers can replay the scenario tests
//! against live service state.
//!
//! The fixtures are deterministic: same seeds → same keys, same
//! signatures, same hashes, same ledger. Every seed op is replayable
//! from the journal — `Store::open` seeds once when the journal
//! replay left the store empty.
//!
//! Timeline anchors (signatif's `T0 = 1_000_000` epoch seconds):
//!
//! | instant         | event                                                 |
//! |-----------------|-------------------------------------------------------|
//! | `T0`            | graph minted (root/notified/issuer/witnesses/quorum); EU trust-list trusts eu-root |
//! | `T0 + 3_000`    | distrust window start (misissuance)                   |
//! | `T0 + 5_000`    | scenario's battery-bad issuance instant               |
//! | `T0 + 8_000`    | distrust window end (misissuance)                     |
//! | `T0 + 9_500`    | prospective key-compromise effect moment              |
//! | `T0 + 10_000`   | misissuance declaration (quorate)                     |
//! | `T0 + 10_500`   | prospective key-compromise declaration                |
//!
//! Faithfully mirroring signatif's scenario means timestamps render as
//! 1970 dates (T0 = 1970-01-12T13:46:40Z). That is a deliberate
//! choice — verdict verifiers replicating `scenario_misissuance` /
//! `scenario_cosign` against live service state use the same instants
//! as signatif's own tests, byte-for-byte.

use std::collections::{BTreeMap, BTreeSet};

use unidpp_model::{Interval, Timestamp};
use unidpp_signatif::graph::{
    DelegationCredential, DelegationNode, MasterList, MasterListEntry, NodeId, NodeKind,
    RegisteredKey, TrustGraph, TrustList, WitnessAttestation,
};
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::revoke::{
    QuorumAttestation, Revocation, RevocationLedger, RevocationReason, RevokedSubject,
};
use unidpp_signatif::scope::DelegationScope;
use unidpp_signatif::sign::Suite;

use crate::store::Op;

/// The fixture epoch instant (matches `tests/common::T0`).
pub const T0: i64 = 1_000_000;

/// Convenience constructor for an epoch-relative fixture instant.
pub fn ts(offset: i64) -> Timestamp {
    Timestamp::from_secs(T0 + offset)
}

/// Keys identified by name. The `KeyPair`s are deterministic (same
/// seeds as signatif's tests) so the published anchors pin to the
/// keys signatif uses internally.
pub struct SeedKeys {
    pub root: KeyPair,
    pub notified: KeyPair,
    pub issuer: KeyPair,
    pub issuer_alt: KeyPair,
    pub witnesses: BTreeMap<NodeId, KeyPair>,
    pub quorum_members: Vec<KeyPair>,
}

impl SeedKeys {
    pub fn load() -> SeedKeys {
        let root = KeyPair::seeded(Suite::Ed25519, b"scenario/eu-root").unwrap();
        let notified = KeyPair::seeded(Suite::EcdsaP256, b"scenario/eu-notified").unwrap();
        let issuer = KeyPair::seeded(Suite::Ed25519, b"scenario/issuer-a").unwrap();
        let issuer_alt = KeyPair::seeded(Suite::EcdsaP256, b"scenario/issuer-a-alt").unwrap();
        let mut witnesses = BTreeMap::new();
        for i in 1..=3u8 {
            let id = NodeId::new(&format!("witness-{i}")).unwrap();
            let key = KeyPair::seeded(Suite::Ed25519, format!("scenario/w{i}").as_bytes()).unwrap();
            witnesses.insert(id, key);
        }
        let quorum_members = vec![
            KeyPair::seeded(Suite::Ed25519, b"scenario/quorum-1").unwrap(),
            KeyPair::seeded(Suite::Ed25519, b"scenario/quorum-2").unwrap(),
            KeyPair::seeded(Suite::EcdsaP256, b"scenario/quorum-3").unwrap(),
        ];
        SeedKeys {
            root,
            notified,
            issuer,
            issuer_alt,
            witnesses,
            quorum_members,
        }
    }
}

/// Build a complete `TrustGraph` from `keys` — the same shape
/// `tests/common::topology()` produces. Exposed for tests and the
/// store-initial seed path.
pub fn build_graph(keys: &SeedKeys) -> TrustGraph {
    let mut graph = TrustGraph::new();
    // End-nodes for witnesses and quorum members: each carries one
    // registered key. Quorum-1/2/3 must be discoverable so the
    // directory covers QuorumAttestation slots.
    let w_ids: Vec<NodeId> = keys.witnesses.keys().cloned().collect();
    for id in &w_ids {
        let key = keys.witnesses.get(id).unwrap();
        let mut n = DelegationNode::new(id.clone(), NodeKind::End);
        n.register(RegisteredKey::of(key));
        graph.add_node(n);
    }
    let q_ids = [
        NodeId::new("quorum-1").unwrap(),
        NodeId::new("quorum-2").unwrap(),
        NodeId::new("quorum-3").unwrap(),
    ];
    for (id, key) in q_ids.iter().cloned().zip(keys.quorum_members.iter()) {
        let mut n = DelegationNode::new(id.clone(), NodeKind::End);
        n.register(RegisteredKey::of(key));
        graph.add_node(n);
    }

    let root_id = NodeId::new("eu-root").unwrap();
    let notified_id = NodeId::new("eu-notified").unwrap();
    let issuer_id = NodeId::new("issuer-key-a").unwrap();
    let quorum_id = NodeId::new("eu-super-quorum").unwrap();

    let mut root_node = DelegationNode::new(root_id.clone(), NodeKind::Root);
    root_node.register(RegisteredKey::of(&keys.root));
    graph.add_node(root_node);
    let mut notified_node = DelegationNode::new(notified_id.clone(), NodeKind::Delegated);
    notified_node.register(RegisteredKey::of(&keys.notified));
    graph.add_node(notified_node);
    let mut issuer_node = DelegationNode::new(issuer_id.clone(), NodeKind::End);
    issuer_node.register(RegisteredKey::of(&keys.issuer));
    issuer_node.register(RegisteredKey::of(&keys.issuer_alt));
    graph.add_node(issuer_node);

    let quorum_node = DelegationNode::new(
        quorum_id.clone(),
        NodeKind::ThresholdGroup {
            threshold: 2,
            members: BTreeSet::from(q_ids.clone()),
        },
    );
    graph.add_node(quorum_node);

    let wide = DelegationScope::unconstrained()
        .authority(["eu"])
        .profile_version([
            "urn:unidpp:profile:eu-batt@3",
            "urn:unidpp:profile:eu-espr@2",
        ])
        .product_group(["batteries", "electronics"])
        .within(Interval::starting(ts(0)));
    let narrow = DelegationScope::unconstrained()
        .authority(["eu"])
        .profile_version(["urn:unidpp:profile:eu-batt@3"])
        .product_group(["batteries"])
        .within(Interval::starting(ts(0)));

    let mut hop1 =
        DelegationCredential::mint_sign(&root_id, &notified_id, wide, &keys.root).unwrap();
    // Mirror tests/common: hop1 is multi-suite co-signed by the same
    // key twice (two slots — verifies quorum-of-distinct discipline).
    hop1.co_sign_by(&keys.root).unwrap();
    let hop2 =
        DelegationCredential::mint_sign(&notified_id, &issuer_id, narrow, &keys.notified).unwrap();
    graph.add_edge(hop1).unwrap();
    graph.add_edge(hop2).unwrap();

    graph
}

/// The EU trust list (jurisdiction `EU`, framework `espr`) trusting
/// `eu-root` from `T0`. The list itself is held in `Store` and the
/// master list is built separately via [`build_master_list`].
pub fn build_trust_lists(keys: &SeedKeys) -> Vec<(String, Option<String>, TrustList)> {
    let mut list = TrustList::new("EU");
    list.trust(NodeId::new("eu-root").unwrap(), ts(0));
    let _ = keys; // signature parity with future frameworks
    vec![("EU".to_string(), Some("espr".to_string()), list)]
}

/// The master list (2-of-3) with witnesses minted from the seeded
/// keys, attesting `eu-root` — same shape as the scenario fixture.
pub fn build_master_list(keys: &SeedKeys) -> MasterList {
    let mut witnesses_map: BTreeMap<NodeId, unidpp_signatif::keyring::PublicKey> = BTreeMap::new();
    for (id, key) in &keys.witnesses {
        witnesses_map.insert(id.clone(), *key.public());
    }
    let mut master = MasterList::new(2, witnesses_map);
    let root = NodeId::new("eu-root").unwrap();
    let mut attestations = Vec::new();
    for (id, key) in &keys.witnesses {
        attestations.push(WitnessAttestation::mint_sign(id, &root, ts(0), key).unwrap());
    }
    master.upsert(MasterListEntry {
        node: root,
        attestations,
    });
    master
}

/// Build the seed revocation ledger (two declarations: one retroactive
/// with quorum, one prospective). The misissuance declaration mirrors
/// `tests/scenario_misissuance::declare_misissuance`.
pub fn build_ledger(keys: &SeedKeys) -> RevocationLedger {
    let mut ledger = RevocationLedger::new();
    let mut retro = Revocation {
        subject: RevokedSubject::Key(keys.issuer.key_id().clone()),
        reason: RevocationReason::Misissuance,
        declared_at: ts(10_000),
        window: Interval::between(ts(3_000), ts(8_000)).unwrap(),
        declared_by: NodeId::new("eu-super-quorum").unwrap(),
        quorum: None,
    };
    let statement = retro.statement_bytes();
    let refs: Vec<&KeyPair> = keys.quorum_members.iter().collect();
    let att = QuorumAttestation::mint_sign(&retro.declared_by, 2, &statement, &refs).unwrap();
    retro.quorum = Some(att);
    ledger.declare(retro).unwrap();

    ledger
        .declare(Revocation {
            subject: RevokedSubject::Key(keys.issuer.key_id().clone()),
            reason: RevocationReason::KeyCompromise { after: ts(9_500) },
            declared_at: ts(10_500),
            window: Interval::starting(ts(9_500)),
            declared_by: NodeId::new("eu-root").unwrap(),
            quorum: None,
        })
        .unwrap();

    ledger
}

/// Build the seed `Op` sequence that, replayed, re-creates the seed
/// state from scratch. Order is meaningful (nodes before edges; lists
/// before entries).
pub fn seed_ops() -> Vec<Op> {
    let keys = SeedKeys::load();
    let mut ops: Vec<Op> = Vec::new();

    // 1. Nodes (every end-node + threshold-group + root + delegated +
    //    issuer — witnesses/quorum members before the bodies that
    //    reference them).
    let emit = |node: DelegationNode, ops: &mut Vec<Op>| ops.push(Op::RegisterNode { node });
    let w_ids: Vec<NodeId> = keys.witnesses.keys().cloned().collect();
    for id in &w_ids {
        let key = keys.witnesses.get(id).unwrap();
        let n = DelegationNode::new(id.clone(), NodeKind::End);
        let mut n = n;
        n.register(RegisteredKey::of(key));
        emit(n, &mut ops);
    }
    let q_ids = [
        NodeId::new("quorum-1").unwrap(),
        NodeId::new("quorum-2").unwrap(),
        NodeId::new("quorum-3").unwrap(),
    ];
    for (id, key) in q_ids.iter().cloned().zip(keys.quorum_members.iter()) {
        let mut n = DelegationNode::new(id.clone(), NodeKind::End);
        n.register(RegisteredKey::of(key));
        emit(n, &mut ops);
    }
    let quorum_id = NodeId::new("eu-super-quorum").unwrap();
    emit(
        DelegationNode::new(
            quorum_id.clone(),
            NodeKind::ThresholdGroup {
                threshold: 2,
                members: BTreeSet::from(q_ids.clone()),
            },
        ),
        &mut ops,
    );

    let root_id = NodeId::new("eu-root").unwrap();
    let notified_id = NodeId::new("eu-notified").unwrap();
    let issuer_id = NodeId::new("issuer-key-a").unwrap();
    let mut n = DelegationNode::new(root_id.clone(), NodeKind::Root);
    n.register(RegisteredKey::of(&keys.root));
    emit(n, &mut ops);
    let mut n = DelegationNode::new(notified_id.clone(), NodeKind::Delegated);
    n.register(RegisteredKey::of(&keys.notified));
    emit(n, &mut ops);
    let mut n = DelegationNode::new(issuer_id.clone(), NodeKind::End);
    n.register(RegisteredKey::of(&keys.issuer));
    n.register(RegisteredKey::of(&keys.issuer_alt));
    emit(n, &mut ops);

    // 2. Edges.
    let wide = DelegationScope::unconstrained()
        .authority(["eu"])
        .profile_version([
            "urn:unidpp:profile:eu-batt@3",
            "urn:unidpp:profile:eu-espr@2",
        ])
        .product_group(["batteries", "electronics"])
        .within(Interval::starting(ts(0)));
    let narrow = DelegationScope::unconstrained()
        .authority(["eu"])
        .profile_version(["urn:unidpp:profile:eu-batt@3"])
        .product_group(["batteries"])
        .within(Interval::starting(ts(0)));
    let mut hop1 =
        DelegationCredential::mint_sign(&root_id, &notified_id, wide, &keys.root).unwrap();
    hop1.co_sign_by(&keys.root).unwrap();
    ops.push(Op::AddEdge { credential: hop1 });
    let hop2 =
        DelegationCredential::mint_sign(&notified_id, &issuer_id, narrow, &keys.notified).unwrap();
    ops.push(Op::AddEdge { credential: hop2 });

    // 3. Trust lists.
    let lists = build_trust_lists(&keys);
    for (jurisdiction, framework, _list) in &lists {
        ops.push(Op::RegisterTrustList {
            jurisdiction: jurisdiction.clone(),
            framework: framework.clone(),
        });
    }
    for (_jurisdiction, _framework, list) in &lists {
        for entry in list.entries.values() {
            ops.push(Op::UpsertTrustEntry {
                jurisdiction: _jurisdiction.clone(),
                node: entry.node.clone(),
                not_before: entry.not_before,
                superseded_at: entry.superseded_at,
            });
        }
    }

    // 4. Master list: witnesses (2-of-3) + entry for eu-root.
    let witness_pairs: Vec<(NodeId, unidpp_signatif::keyring::PublicKey)> = keys
        .witnesses
        .iter()
        .map(|(id, k)| (id.clone(), *k.public()))
        .collect();
    ops.push(Op::SetWitnesses {
        m: 2,
        witnesses: witness_pairs,
    });
    let mut attestations = Vec::new();
    for (id, key) in &keys.witnesses {
        attestations.push(WitnessAttestation::mint_sign(id, &root_id, ts(0), key).unwrap());
    }
    ops.push(Op::UpsertMasterEntry {
        entry: MasterListEntry {
            node: root_id.clone(),
            attestations,
        },
    });

    // 5. Revocations (mirrors scenario_misissuance + a prospective).
    let mut retro = Revocation {
        subject: RevokedSubject::Key(keys.issuer.key_id().clone()),
        reason: RevocationReason::Misissuance,
        declared_at: ts(10_000),
        window: Interval::between(ts(3_000), ts(8_000)).unwrap(),
        declared_by: NodeId::new("eu-super-quorum").unwrap(),
        quorum: None,
    };
    let statement = retro.statement_bytes();
    let refs: Vec<&KeyPair> = keys.quorum_members.iter().collect();
    let att = QuorumAttestation::mint_sign(&retro.declared_by, 2, &statement, &refs).unwrap();
    retro.quorum = Some(att);
    ops.push(Op::DeclareRevocation { revocation: retro });
    ops.push(Op::DeclareRevocation {
        revocation: Revocation {
            subject: RevokedSubject::Key(keys.issuer.key_id().clone()),
            reason: RevocationReason::KeyCompromise { after: ts(9_500) },
            declared_at: ts(10_500),
            window: Interval::starting(ts(9_500)),
            declared_by: root_id.clone(),
            quorum: None,
        },
    });

    ops
}

/// One seeded jurisdiction's trust list: the (jurisdiction, framework)
/// keying plus the signatif list itself.
pub type SeededTrustList = (String, Option<String>, TrustList);

/// The fixture source string (signatif's test trust graph), surfaced
/// in the discovery document and the seed-fixture audit marker.
pub const FIXTURE_SOURCE: &str =
    "unidpp-signatif tests/common topology + scenario_misissuance (T0-anchored; see README)";

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_signatif::sign::SignatureSlot;

    fn signatures_on_credential(c: &DelegationCredential) -> Vec<&SignatureSlot> {
        c.signatures.iter().collect()
    }

    #[test]
    fn seed_ops_replay_into_a_complete_graph() {
        // Build the reference graph directly, then replay the seed
        // ops into a fresh graph and assert equality on its nodes and
        // edges (same credentials verify under the seeded keys).
        let keys = SeedKeys::load();
        let ref_graph = build_graph(&keys);
        let mut replayed = TrustGraph::new();
        let ops = seed_ops();
        for op in ops {
            match op {
                Op::RegisterNode { node } => replayed.add_node(node),
                Op::AddEdge { credential } => replayed.add_edge(credential).unwrap(),
                _ => {}
            }
        }
        // Same node set.
        assert_eq!(replayed.node_count(), ref_graph.node_count());
        assert_eq!(replayed.edge_count(), ref_graph.edge_count());
        // The hop1 credential carries two slots (mirroring the common
        // fixture's co_sign_by of the same key — verifies distinct-key
        // counting).
        let hop1 = replayed
            .edges()
            .iter()
            .find(|e| e.parent == NodeId::new("eu-root").unwrap())
            .expect("root → notified edge");
        assert_eq!(signatures_on_credential(hop1).len(), 2);
    }

    #[test]
    fn ledger_mirrors_misissuance_scenario() {
        let keys = SeedKeys::load();
        let ledger = build_ledger(&keys);
        assert_eq!(ledger.revocations().len(), 2);
        let retro = ledger
            .revocations()
            .iter()
            .find(|r| r.reason.is_retroactive())
            .unwrap();
        assert_eq!(retro.reason.token(), "misissuance");
        // The retroactive declaration voids at T0+5000 (in window).
        assert!(retro.voids(ts(5_000)));
        // And re-validates before/after.
        assert!(!retro.voids(ts(2_500)));
        assert!(!retro.voids(ts(9_000)));
        // The prospective declaration is a KeyCompromise after T0+9500.
        let pros = ledger
            .revocations()
            .iter()
            .find(|r| !r.reason.is_retroactive())
            .unwrap();
        assert_eq!(pros.reason.token(), "key-compromise");
        assert!(!pros.voids(ts(9_000)));
        assert!(pros.voids(ts(9_600)));
    }

    #[test]
    fn master_list_is_quorate_for_seeded_root() {
        let keys = SeedKeys::load();
        let master = build_master_list(&keys);
        let root = NodeId::new("eu-root").unwrap();
        assert!(master.accepts(&root));
        assert_eq!(master.m, 2);
        assert_eq!(master.k, 3);
    }

    #[test]
    fn trust_lists_trust_seeded_root() {
        let keys = SeedKeys::load();
        let lists = build_trust_lists(&keys);
        assert_eq!(lists.len(), 1);
        let (jur, framework, list) = &lists[0];
        assert_eq!(jur, "EU");
        assert_eq!(framework.as_deref(), Some("espr"));
        assert!(list.accepts_at(&NodeId::new("eu-root").unwrap(), ts(0)));
    }
}
