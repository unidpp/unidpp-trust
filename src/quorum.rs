//! Quorum verdicts: how the service decides an attestation is quorate.
//!
//! SIGNATIF's [`QuorumAttestation`] model covers the **member-key
//! form**: `threshold` distinct member keys' slots verify in the
//! [`SigningDomain::Quorum`] domain over the attestation's canonical
//! bytes, resolved through the trust graph's key directory.
//!
//! The **threshold-ceremony form** integrates the crate's own M-of-K
//! cryptography ([`unidpp_signatif::threshold`] — Feldman VSS,
//! threshold Schnorr partials) through the Confium seam's
//! [`RealCeremony`](unidpp_signatif::confium::real::RealCeremony): a
//! qualifying set of `M` members combines its partials into **one
//! standard Ed25519 group signature** under the ceremony's group key.
//! That signature *is* the proof that `M` members acted — fewer than
//! `M` shares mathematically cannot produce one — so the attestation
//! carries a single slot under the group key, and the threshold it
//! proves is the ceremony group's, not a slot count.
//!
//! The two forms are distinguished by **where the verifying key
//! lives**, which is graph state the service already owns:
//!
//! | Form | Verifying key registered… | Quorate when |
//! |---|---|---|
//! | member keys | on the members' own nodes (resolvable through the whole-graph directory) | `threshold` distinct verifying member keys |
//! | threshold group | **on the quorum node itself**, whose kind is a `ThresholdGroup` with the same threshold | at least one slot verifies under it |
//!
//! A key registered on the quorum node counts only toward the group
//! form (it is the group key, not a member key), so the forms stay
//! mutually exclusive — an attestation is quorate through one or the
//! other, never a mix. The seed topology keeps quorum nodes keyless
//! (members' keys live on their end-nodes), so the member-key form is
//! unchanged by this extension.
//!
//! Ceremony operators produce the group form with the
//! `quorum-ceremony` binary (this package's `src/bin/`): it runs a
//! real ceremony over the attestation's canonical bytes and emits the
//! `POST /nodes` body (the quorum node pinning the group key) plus the
//! `POST /revocations` body (the attestation with the group slot).

use unidpp_signatif::graph::{KeyDirectory, NodeKind, TrustGraph};
use unidpp_signatif::revoke::QuorumAttestation;
use unidpp_signatif::sign::{SignatureSlot, SigningDomain};

/// Which attestation form reached (or failed to reach) the threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumForm {
    /// Distinct member-key slots (the classic SIGNATIF form).
    MemberKeys,
    /// A threshold-ceremony group signature under the quorum node's
    /// registered group key.
    ThresholdGroup,
}

impl QuorumForm {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            QuorumForm::MemberKeys => "member-keys",
            QuorumForm::ThresholdGroup => "threshold-group",
        }
    }
}

/// The live verdict over one attestation, against one statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumVerdict {
    /// The form the quorate conclusion rests on (`MemberKeys` when no
    /// verifying group slot certifies — the member count is what the
    /// verdict then depends on).
    pub form: QuorumForm,
    /// Distinct verifying member keys (keys resolvable through the
    /// whole-graph directory but NOT registered on the quorum node).
    pub member_verified: usize,
    /// Whether a group-key slot verified under a quorum node whose
    /// declared threshold matches the attestation's.
    pub group_verified: bool,
    /// The attestation's claimed threshold.
    pub threshold: usize,
    /// Whether the attestation is quorate.
    pub quorate: bool,
}

impl QuorumVerdict {
    /// Human summary for store errors and logs.
    pub fn summary(&self) -> String {
        match self.form {
            QuorumForm::MemberKeys => {
                format!(
                    "{} member key(s) verified, threshold {}",
                    self.member_verified, self.threshold
                )
            }
            QuorumForm::ThresholdGroup => format!(
                "threshold-group signature verified ({} of the group's members acted), threshold {}",
                self.threshold, self.threshold
            ),
        }
    }
}

/// Judge `quorum` against `statement` over the live graph.
///
/// Member-key counting matches [`QuorumAttestation::is_quorate`]
/// exactly for keyless quorum nodes (the seed topology), and excludes
/// keys registered on the quorum node so the group key is never also
/// counted as a member. The group form additionally requires the
/// quorum node's `ThresholdGroup` threshold to equal the
/// attestation's: the canonical bytes bind the *claimed* threshold,
/// the graph binds the *asserted* one, and a disagreement must not
/// certify.
pub fn verdict(graph: &TrustGraph, quorum: &QuorumAttestation, statement: &[u8]) -> QuorumVerdict {
    let payload = QuorumAttestation::canonical_bytes(statement, &quorum.quorum, quorum.threshold);
    let directory: KeyDirectory = graph.key_directory();
    let node = graph.node(&quorum.quorum);
    let node_threshold = node.and_then(|n| match &n.kind {
        NodeKind::ThresholdGroup { threshold, .. } => Some(*threshold),
        _ => None,
    });

    // Group form: a slot verifying under a key registered on the quorum
    // node itself. The slot verifies as standard Ed25519 over the same
    // canonical bytes a member slot would — the difference is only the
    // key (the ceremony's group key) and what producing that signature
    // required (a qualifying set).
    let mut group_verified = false;
    if let Some(n) = node {
        for slot in &quorum.signatures {
            if let Some(public) = n.key(&slot.key_id) {
                if slot_verifies(slot, &payload, public) {
                    group_verified = true;
                    break;
                }
            }
        }
    }
    // The graph must assert the same threshold the attestation claims.
    let group_certifies = group_verified && node_threshold == Some(quorum.threshold);

    // Member form: distinct verifying keys resolvable through the
    // directory, excluding the quorum node's own (group) keys.
    let mut members: std::collections::BTreeSet<_> = Default::default();
    let quorum_keys: Vec<_> = node
        .map(|n| n.keys.iter().map(|k| k.key_id.clone()).collect())
        .unwrap_or_default();
    for slot in &quorum.signatures {
        if quorum_keys.contains(&slot.key_id) {
            continue;
        }
        if let Some(public) = directory.resolve(&slot.key_id) {
            if slot_verifies(slot, &payload, public) {
                members.insert(slot.key_id.clone());
            }
        }
    }
    let member_verified = members.len();

    let (form, quorate) = if group_certifies {
        (QuorumForm::ThresholdGroup, true)
    } else {
        (QuorumForm::MemberKeys, member_verified >= quorum.threshold)
    };
    QuorumVerdict {
        form,
        member_verified,
        group_verified,
        threshold: quorum.threshold,
        quorate,
    }
}

fn slot_verifies(
    slot: &SignatureSlot,
    payload: &[u8],
    public: &unidpp_signatif::keyring::PublicKey,
) -> bool {
    slot.verify(SigningDomain::Quorum, payload, public).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use unidpp_signatif::graph::{DelegationNode, NodeId, RegisteredKey};
    use unidpp_signatif::keyring::{KeyId, KeyPair};
    use unidpp_signatif::sign::Suite;

    fn members(n: usize) -> Vec<KeyPair> {
        (0..n)
            .map(|i| KeyPair::seeded(Suite::Ed25519, format!("qv-{i}").as_bytes()).unwrap())
            .collect()
    }

    fn quorum_graph(
        quorum_id: &str,
        threshold: usize,
        member_keys: &[KeyPair],
        group_key: Option<&unidpp_signatif::keyring::PublicKey>,
    ) -> TrustGraph {
        let mut graph = TrustGraph::new();
        let member_ids: Vec<NodeId> = (0..member_keys.len())
            .map(|i| NodeId::new(&format!("m{i}")).unwrap())
            .collect();
        for (id, key) in member_ids.iter().zip(member_keys.iter()) {
            let mut n = DelegationNode::new(id.clone(), NodeKind::End);
            n.register(RegisteredKey::of(key));
            graph.add_node(n);
        }
        let mut node = DelegationNode::new(
            NodeId::new(quorum_id).unwrap(),
            NodeKind::ThresholdGroup {
                threshold,
                members: BTreeSet::from_iter(member_ids.iter().cloned()),
            },
        );
        if let Some(g) = group_key {
            node.register(RegisteredKey {
                key_id: KeyId::of(g),
                public: *g,
            });
        }
        graph.add_node(node);
        graph
    }

    #[test]
    fn member_key_form_matches_is_quorate_on_keyless_quorum_nodes() {
        let members = members(3);
        let statement = b"statement".to_vec();
        let quorum = NodeId::new("q").unwrap();
        let graph = quorum_graph("q", 2, &members, None);
        let att = QuorumAttestation::mint_sign(&quorum, 2, &statement, &[&members[0], &members[1]])
            .unwrap();
        let v = verdict(&graph, &att, &statement);
        assert_eq!(v.form, QuorumForm::MemberKeys);
        assert_eq!(v.member_verified, 2);
        assert!(v.quorate);
        assert_eq!(
            v.quorate,
            att.is_quorate(&statement, &graph.key_directory()).unwrap()
        );
        // Below threshold: one member alone.
        let solo = QuorumAttestation::mint_sign(&quorum, 2, &statement, &[&members[0]]).unwrap();
        let v = verdict(&graph, &solo, &statement);
        assert_eq!(v.member_verified, 1);
        assert!(!v.quorate);
    }

    #[test]
    fn group_key_form_certifies_one_slot_when_thresholds_agree() {
        // A 2-of-3 ceremony: derive the group through the real Confium
        // seam and aggregate a qualifying pair.
        use unidpp_signatif::confium::real::RealCeremony;
        use unidpp_signatif::confium::{
            CeremonyCoordinator, CeremonyKind, CeremonyStatement, QuorumSpec, SessionInit,
        };
        let quorum = NodeId::new("ceremony-q").unwrap();
        let spec = QuorumSpec {
            quorum_id: quorum.clone(),
            threshold: 2,
            members: vec![
                NodeId::new("m0").unwrap(),
                NodeId::new("m1").unwrap(),
                NodeId::new("m2").unwrap(),
            ],
        };
        let statement = b"retroactive distrust statement".to_vec();
        let payload = QuorumAttestation::canonical_bytes(&statement, &quorum, 2);
        let mut ceremony = RealCeremony::new(None);
        let session = ceremony
            .create_session(SessionInit {
                kind: CeremonyKind::Sign,
                statement: CeremonyStatement {
                    label: "test".into(),
                    payload: payload.clone(),
                },
                quorum: spec,
                expires_at: None,
            })
            .unwrap();
        for signer in [&NodeId::new("m0").unwrap(), &NodeId::new("m1").unwrap()] {
            ceremony
                .submit_commitment(&session, ceremony.commitment_for(&session, signer).unwrap())
                .unwrap();
        }
        for signer in [&NodeId::new("m0").unwrap(), &NodeId::new("m1").unwrap()] {
            ceremony
                .submit_share(&session, ceremony.share_for(&session, signer).unwrap())
                .unwrap();
        }
        let aggregated = ceremony.aggregate(&session).unwrap();
        let att = QuorumAttestation {
            quorum: quorum.clone(),
            threshold: 2,
            signatures: vec![aggregated.to_slot()],
        };

        // The quorum node pins the ceremony's group key.
        let group_public = aggregated.group_key;
        let graph = quorum_graph("ceremony-q", 2, &members(3), Some(&group_public));
        let v = verdict(&graph, &att, &statement);
        assert_eq!(v.form, QuorumForm::ThresholdGroup);
        assert!(v.group_verified);
        assert_eq!(v.member_verified, 0, "the group key is not a member");
        assert!(v.quorate);
        // The single slot is what signatif's own counter would call
        // "1 verified" — the group form is the service's integration of
        // the ceremony output, not a slot count.
        assert!(!att
            .is_quorate(&statement, &graph.key_directory())
            .unwrap_or(false));
    }

    #[test]
    fn group_form_requires_graph_registration_and_matching_threshold() {
        use unidpp_signatif::confium::real::RealCeremony;
        use unidpp_signatif::confium::{
            CeremonyCoordinator, CeremonyKind, CeremonyStatement, QuorumSpec, SessionInit,
        };
        let quorum = NodeId::new("reg-q").unwrap();
        let spec = QuorumSpec {
            quorum_id: quorum.clone(),
            threshold: 2,
            members: vec![
                NodeId::new("m0").unwrap(),
                NodeId::new("m1").unwrap(),
                NodeId::new("m2").unwrap(),
            ],
        };
        let statement = b"s".to_vec();
        let payload = QuorumAttestation::canonical_bytes(&statement, &quorum, 2);
        let mut ceremony = RealCeremony::new(None);
        let session = ceremony
            .create_session(SessionInit {
                kind: CeremonyKind::Sign,
                statement: CeremonyStatement {
                    label: "t".into(),
                    payload,
                },
                quorum: spec,
                expires_at: None,
            })
            .unwrap();
        for signer in [&NodeId::new("m0").unwrap(), &NodeId::new("m2").unwrap()] {
            ceremony
                .submit_commitment(&session, ceremony.commitment_for(&session, signer).unwrap())
                .unwrap();
        }
        for signer in [&NodeId::new("m0").unwrap(), &NodeId::new("m2").unwrap()] {
            ceremony
                .submit_share(&session, ceremony.share_for(&session, signer).unwrap())
                .unwrap();
        }
        let aggregated = ceremony.aggregate(&session).unwrap();
        let att = QuorumAttestation {
            quorum: quorum.clone(),
            threshold: 2,
            signatures: vec![aggregated.to_slot()],
        };

        // Unregistered group key: nothing certifies.
        let graph = quorum_graph("reg-q", 2, &members(3), None);
        let v = verdict(&graph, &att, &statement);
        assert!(!v.quorate, "the pinned group key is load-bearing");
        assert_eq!(v.member_verified, 0);

        // Threshold disagreement between the graph's quorum node and
        // the attestation: refused.
        let graph = quorum_graph("reg-q", 3, &members(3), Some(&aggregated.group_key));
        let v = verdict(&graph, &att, &statement);
        assert!(v.group_verified, "the signature itself verifies");
        assert!(!v.quorate, "claimed 2, graph asserts 3");
        assert_eq!(v.form, QuorumForm::MemberKeys);

        // A quorum node that is not a threshold group cannot certify
        // the group form either (an ordinary root node's key is a
        // member-class key).
        let mut graph = TrustGraph::new();
        let mut plain = DelegationNode::new(quorum.clone(), NodeKind::Root);
        plain.register(RegisteredKey {
            key_id: KeyId::of(&aggregated.group_key),
            public: aggregated.group_key,
        });
        graph.add_node(plain);
        let v = verdict(&graph, &att, &statement);
        assert!(!v.quorate);
    }
}
