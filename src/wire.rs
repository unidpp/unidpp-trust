//! Wire layer: conversions between SIGNATIF types and JSON `Value`.
//!
//! Doctrine: **avoid `PublicKey`'s serde impl**. SIGNATIF renders
//! public keys as `"<suite>:<sha256(key) hex>"` (a fingerprint) but
//! deserialises them back as raw key bytes from `PublicKey::from_bytes`
//! — the round-trip is asymmetric and silently mints a wrong key for
//! the 32-byte case. Every wire form here carries the raw key as hex
//! (32 bytes for Ed25519, 65 bytes for SEC1 uncompressed P-256) and
//! rebuilds via [`PublicKey::from_bytes`] — which is the exact form
//! `unidpp_cli --anchor` accepts, so a verifier pinning either role
//! uses one codec end-to-end.
//!
//! Other SIGNATIF types serialise round-trip-cleanly and are passed
//! through `serde_json::to_value` / `::from_value`; their wire form is
//! identical to `tests/common` and the CLI's offline fixtures.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};
use unidpp_model::Timestamp;
use unidpp_signatif::graph::{
    DelegationCredential, DelegationNode, MasterList, MasterListEntry, NodeId, NodeKind,
    RegisteredKey, TrustList, WitnessAttestation,
};
use unidpp_signatif::keyring::{KeyId, KeyPair, PublicKey};
use unidpp_signatif::revoke::{QuorumAttestation, Revocation, RevocationReason, RevokedSubject};
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};
use unidpp_signatif::SignatifError;

use crate::hex::{hex_decode, hex_encode};
use crate::time::Timestamp as Ts;

// ============================================================================
// PublicKey / SignatureSlot
// ============================================================================

/// Render a public key as `{suite, public}` with raw hex bytes. The
/// asymmetric `PublicKey` serde is intentionally avoided.
pub fn public_to_value(public: &PublicKey) -> Value {
    json!({
        "suite": public.suite().to_string(),
        "public": hex_encode(public.as_bytes()),
        "public_len": public.as_bytes().len(),
    })
}

pub fn public_from_value(v: &Value) -> Result<PublicKey, String> {
    let obj = v.as_object().ok_or("public key must be an object")?;
    let suite = obj
        .get("suite")
        .and_then(Value::as_str)
        .ok_or("public key `suite` is required")?;
    let hex = obj
        .get("public")
        .and_then(Value::as_str)
        .ok_or("public key `public` (hex) is required")?;
    let bytes = hex_decode(hex)?;
    PublicKey::from_bytes(&bytes).map_err(|e| e.to_string())?;
    // Round-trip sanity: bytes match suite.
    let parsed = PublicKey::from_bytes(&bytes).map_err(|e| e.to_string())?;
    let parsed_suite = parsed.suite().to_string();
    if parsed_suite.to_ascii_lowercase().replace('-', "")
        != suite.to_ascii_lowercase().replace('-', "")
    {
        return Err(format!(
            "public key suite mismatch: declared `{suite}`, bytes are `{}`",
            parsed.suite()
        ));
    }
    Ok(parsed)
}

/// Render a signature slot as `{suite, key_id, signature}` with hex
/// bytes (the slot's `signature: Option<Vec<u8>>` is JSON-array of
/// integers when round-tripped via `serde_json` — opaque hex is
/// friendlier to API clients and matches the issuer's CLI).
pub fn slot_to_value(slot: &SignatureSlot) -> Value {
    let mut m = Map::new();
    m.insert("suite".into(), json!(slot.suite.to_string()));
    m.insert("key_id".into(), json!(slot.key_id.to_string()));
    m.insert(
        "signature".into(),
        json!(slot.signature.as_ref().map(|s| hex_encode(s))),
    );
    Value::Object(m)
}

pub fn slot_from_value(v: &Value) -> Result<SignatureSlot, String> {
    let obj = v.as_object().ok_or("signature slot must be an object")?;
    let suite = obj
        .get("suite")
        .and_then(Value::as_str)
        .ok_or("`suite` is required")?;
    let key_id_raw = obj
        .get("key_id")
        .and_then(Value::as_str)
        .ok_or("`key_id` is required")?;
    let suite = Suite::parse_token(suite).map_err(|e| e.to_string())?;
    let key_id = KeyId::new(key_id_raw).map_err(|e| e.to_string())?;
    let signature = match obj.get("signature") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(hex_decode(s).map_err(|e| format!("`signature`: {e}"))?),
        Some(_) => return Err("`signature` must be a hex string or null".into()),
    };
    if let Some(sig) = &signature {
        if sig.len() != suite.signature_len() {
            return Err(format!(
                "signature length {} does not match the {} framing budget {}",
                sig.len(),
                suite,
                suite.signature_len()
            ));
        }
    }
    Ok(SignatureSlot {
        suite,
        key_id,
        signature,
    })
}

// ============================================================================
// Subject references (key:k-... | node:x | passport:urn:...)
// ============================================================================

/// Render the canonical `RevokedSubject` to JSON `{kind, id, label}`.
pub fn revoked_subject_to_value(subject: &RevokedSubject) -> Value {
    match subject {
        RevokedSubject::Key(k) => json!({
            "kind": "key",
            "id": k.to_string(),
            "label": format!("key:{}", k.as_str()),
        }),
        RevokedSubject::Node(n) => json!({
            "kind": "node",
            "id": n.to_string(),
            "label": format!("node:{}", n.as_str()),
        }),
        RevokedSubject::Passport(p) => json!({
            "kind": "passport",
            "id": p.to_string(),
            "label": format!("passport:{}", p.as_str()),
        }),
        RevokedSubject::Condition { node, condition } => json!({
            "kind": "condition",
            "id": format!("{node}:`{condition}`"),
            "label": format!("condition:{node}:`{condition}`"),
            // The structured form: the condition rides as its own
            // serde shape, so the round trip never parses the display
            // string.
            "node": node.to_string(),
            "condition": serde_json::to_value(condition)
                .expect("scope conditions are plain serde data"),
        }),
    }
}

/// Parse the canonical `{kind, id}` form.
pub fn revoked_subject_from_value(v: &Value) -> Result<RevokedSubject, String> {
    let obj = v.as_object().ok_or("subject must be an object")?;
    let kind = obj
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("`kind` is required")?;
    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or("`id` is required")?;
    match kind {
        "key" => Ok(RevokedSubject::Key(
            KeyId::new(id).map_err(|e| e.to_string())?,
        )),
        "node" => Ok(RevokedSubject::Node(
            NodeId::new(id).map_err(|e| e.to_string())?,
        )),
        "passport" => Ok(RevokedSubject::Passport(
            unidpp_model::PassportId::new(id).map_err(|e| format!("`id`: {e}"))?,
        )),
        "condition" => {
            let node = NodeId::new(
                obj.get("node")
                    .and_then(Value::as_str)
                    .ok_or("`node` is required for `condition`")?,
            )
            .map_err(|e| format!("`node`: {e}"))?;
            let condition: unidpp_signatif::scope::ScopeCondition = serde_json::from_value(
                obj.get("condition")
                    .cloned()
                    .ok_or("`condition` (the scope-condition object) is required")?,
            )
            .map_err(|e| format!("`condition`: {e}"))?;
            Ok(RevokedSubject::Condition { node, condition })
        }
        other => Err(format!(
            "unknown subject kind `{other}` (expected key|node|passport|condition)"
        )),
    }
}

/// Parse the label form `key:k-..` | `node:x` | `passport:urn:..`.
pub fn revoked_subject_from_label(s: &str) -> Result<RevokedSubject, String> {
    let (kind, id) = s
        .split_once(':')
        .ok_or_else(|| format!("subject `{s}` must be `kind:id`"))?;
    match kind.trim() {
        "key" => Ok(RevokedSubject::Key(
            KeyId::new(id).map_err(|e| e.to_string())?,
        )),
        "node" => Ok(RevokedSubject::Node(
            NodeId::new(id).map_err(|e| e.to_string())?,
        )),
        "passport" => Ok(RevokedSubject::Passport(
            unidpp_model::PassportId::new(id).map_err(|e| format!("`id`: {e}"))?,
        )),
        // The label form cannot carry a condition subject (its id
        // embeds the condition's display string, which is not a
        // parseable grammar) — the structured JSON form carries it.
        "condition" => Err(
            "condition subjects use the structured form (kind: \"condition\", node, condition), \
             not the label form"
                .to_string(),
        ),
        other => Err(format!(
            "unknown subject kind `{other}` (expected key|node|passport)"
        )),
    }
}

// ============================================================================
// Revocation reason
// ============================================================================

/// Render a reason as `{token, retroactive, …params}` so the live
/// retroactivity semantics are visible in the wire form.
pub fn reason_to_value(reason: &RevocationReason) -> Value {
    let mut m = Map::new();
    m.insert("token".into(), json!(reason.token()));
    m.insert("retroactive".into(), json!(reason.is_retroactive()));
    match reason {
        RevocationReason::KeyCompromise { after } => {
            m.insert("after".into(), json!(ts_string(after)));
        }
        RevocationReason::AuthorityCompromised { detected_at } => {
            m.insert("detected_at".into(), json!(ts_string(detected_at)));
        }
        RevocationReason::Supersession { by } => {
            m.insert("by".into(), json!(by.to_string()));
        }
        RevocationReason::Cessation
        | RevocationReason::AffiliationChange
        | RevocationReason::Misissuance
        | RevocationReason::FraudulentIssuance
        | RevocationReason::ConditionWithdrawal => {}
    }
    Value::Object(m)
}

/// Parse a `{token, after/detected_at/by}` shape. Tokens match
/// [`RevocationReason::token`].
pub fn reason_from_value(v: &Value) -> Result<RevocationReason, String> {
    let obj = v.as_object().ok_or("reason must be an object")?;
    let token = obj
        .get("token")
        .and_then(Value::as_str)
        .ok_or("`token` is required")?;
    let req_ts = |key: &str| -> Result<Timestamp, String> {
        let raw = obj
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("`{key}` is required for `{token}`"))?;
        ts_parse(raw).map_err(|e| format!("`{key}`: {e}"))
    };
    match token {
        "key-compromise" => Ok(RevocationReason::KeyCompromise {
            after: req_ts("after")?,
        }),
        "cessation" => Ok(RevocationReason::Cessation),
        "supersession" => Ok(RevocationReason::Supersession {
            by: NodeId::new(
                obj.get("by")
                    .and_then(Value::as_str)
                    .ok_or("`by` is required for `supersession`")?,
            )
            .map_err(|e| format!("`by`: {e}"))?,
        }),
        "affiliation-change" => Ok(RevocationReason::AffiliationChange),
        "misissuance" => Ok(RevocationReason::Misissuance),
        "fraudulent-issuance" => Ok(RevocationReason::FraudulentIssuance),
        "authority-compromised" => Ok(RevocationReason::AuthorityCompromised {
            detected_at: req_ts("detected_at")?,
        }),
        "condition-withdrawal" => Ok(RevocationReason::ConditionWithdrawal),
        other => Err(format!("unknown reason token `{other}`")),
    }
}

// ============================================================================
// Interval / Timestamp helpers
// ============================================================================

pub fn ts_string(t: &Timestamp) -> String {
    t.to_string()
}

pub fn ts_parse(s: &str) -> Result<Timestamp, String> {
    Ts::parse(s)
        .map(|t| t.to_model())
        .map_err(|e| e.to_string())
}

/// Render an Interval as `{start, end, open}`.
pub fn interval_to_value(i: &unidpp_model::Interval) -> Value {
    json!({
        "start": i.from.to_string(),
        "end": i.to.map(|t| t.to_string()),
        "open": i.to.is_none(),
    })
}

pub fn interval_from_value(v: &Value) -> Result<unidpp_model::Interval, String> {
    let obj = v.as_object().ok_or("interval must be an object")?;
    let start_raw = obj
        .get("start")
        .and_then(Value::as_str)
        .ok_or("`start` is required")?;
    let from = ts_parse(start_raw)?;
    let to = match obj.get("end") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(ts_parse(s)?),
        Some(_) => return Err("`end` must be an RFC 3339 string or null".into()),
    };
    if let Some(t) = to {
        if t < from {
            return Err(format!("window end {t} is before start {from}"));
        }
        unidpp_model::Interval::between(from, t).map_err(|e| e.to_string())
    } else {
        Ok(unidpp_model::Interval::starting(from))
    }
}

// ============================================================================
// Quorum attestation
// ============================================================================

pub fn quorum_to_value(q: &QuorumAttestation) -> Value {
    json!({
        "quorum": q.quorum.to_string(),
        "threshold": q.threshold,
        "signatures": q.signatures.iter().map(slot_to_value).collect::<Vec<_>>(),
    })
}

pub fn quorum_from_value(v: &Value) -> Result<QuorumAttestation, String> {
    let obj = v
        .as_object()
        .ok_or("quorum attestation must be an object")?;
    let quorum = NodeId::new(
        obj.get("quorum")
            .and_then(Value::as_str)
            .ok_or("`quorum` is required")?,
    )
    .map_err(|e| format!("`quorum`: {e}"))?;
    let threshold = obj
        .get("threshold")
        .and_then(Value::as_u64)
        .ok_or("`threshold` (number) is required")? as usize;
    let signatures = obj
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or("`signatures` array is required")?;
    let signatures = signatures
        .iter()
        .map(slot_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(QuorumAttestation {
        quorum,
        threshold,
        signatures,
    })
}

// ============================================================================
// Revocation (full envelope)
// ============================================================================

pub fn revocation_to_value(r: &Revocation) -> Value {
    json!({
        "subject": revoked_subject_to_value(&r.subject),
        "reason": reason_to_value(&r.reason),
        "declared_at": ts_string(&r.declared_at),
        "declared_by": r.declared_by.to_string(),
        "window": interval_to_value(&r.window),
        "quorum": r.quorum.as_ref().map(quorum_to_value),
    })
}

pub fn revocation_from_value(v: &Value) -> Result<Revocation, String> {
    let obj = v.as_object().ok_or("revocation must be an object")?;
    let subject = revoked_subject_from_value(obj.get("subject").ok_or("`subject` is required")?)?;
    let reason = reason_from_value(obj.get("reason").ok_or("`reason` is required")?)?;
    let declared_at = ts_parse(
        obj.get("declared_at")
            .and_then(Value::as_str)
            .ok_or("`declared_at` (RFC 3339) is required")?,
    )?;
    let declared_by = NodeId::new(
        obj.get("declared_by")
            .and_then(Value::as_str)
            .ok_or("`declared_by` is required")?,
    )
    .map_err(|e| format!("`declared_by`: {e}"))?;
    let window = interval_from_value(obj.get("window").ok_or("`window` is required")?)?;
    let quorum = match obj.get("quorum") {
        None | Some(Value::Null) => None,
        Some(v) => Some(quorum_from_value(v)?),
    };
    Ok(Revocation {
        subject,
        reason,
        declared_at,
        declared_by,
        window,
        quorum,
    })
}

// ============================================================================
// Trust graph: nodes, edges, witness attestations
// ============================================================================

pub fn node_kind_to_value(kind: &NodeKind) -> Value {
    match kind {
        NodeKind::Root => json!("root"),
        NodeKind::Delegated => json!("delegated"),
        NodeKind::End => json!("end"),
        NodeKind::ThresholdGroup { threshold, members } => json!({
            "threshold_group": {
                "threshold": *threshold,
                "members": members.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
            }
        }),
    }
}

pub fn node_kind_from_value(v: &Value) -> Result<NodeKind, String> {
    match v {
        Value::String(s) => match s.as_str() {
            "root" => Ok(NodeKind::Root),
            "delegated" => Ok(NodeKind::Delegated),
            "end" => Ok(NodeKind::End),
            other => Err(format!("unknown node kind `{other}`")),
        },
        Value::Object(o) => {
            let g = o
                .get("threshold_group")
                .and_then(Value::as_object)
                .ok_or("`threshold_group` object is required")?;
            let threshold =
                g.get("threshold")
                    .and_then(Value::as_u64)
                    .ok_or("`threshold_group.threshold` is required")? as usize;
            let members = g
                .get("members")
                .and_then(Value::as_array)
                .ok_or("`threshold_group.members` array is required")?;
            let members: BTreeSet<NodeId> = members
                .iter()
                .map(|m| {
                    m.as_str()
                        .ok_or_else(|| "members must be node-id strings".to_string())
                        .and_then(|s| NodeId::new(s).map_err(|e| e.to_string()))
                })
                .collect::<Result<_, _>>()?;
            Ok(NodeKind::ThresholdGroup { threshold, members })
        }
        _ => Err("node kind must be a string or object".into()),
    }
}

pub fn node_to_value(node: &DelegationNode) -> Value {
    json!({
        "id": node.id.to_string(),
        "kind": node_kind_to_value(&node.kind),
        "keys": node.keys.iter().map(|k| json!({
            "key_id": k.key_id.to_string(),
            "suite": k.public.suite().to_string(),
            "public": hex_encode(k.public.as_bytes()),
            "public_len": k.public.as_bytes().len(),
        })).collect::<Vec<_>>(),
    })
}

pub fn node_from_value(v: &Value) -> Result<DelegationNode, String> {
    let obj = v.as_object().ok_or("node must be an object")?;
    let id = NodeId::new(
        obj.get("id")
            .and_then(Value::as_str)
            .ok_or("`id` is required")?,
    )
    .map_err(|e| format!("`id`: {e}"))?;
    let kind = node_kind_from_value(obj.get("kind").ok_or("`kind` is required")?)?;
    let mut node = DelegationNode::new(id.clone(), kind);
    if let Some(arr) = obj.get("keys").and_then(Value::as_array) {
        for k in arr {
            let obj = k.as_object().ok_or("`keys[].key_id` must be an object")?;
            let key_id = KeyId::new(
                obj.get("key_id")
                    .and_then(Value::as_str)
                    .ok_or("`key_id` is required")?,
            )
            .map_err(|e| format!("`key_id`: {e}"))?;
            let public = public_from_value(&Value::Object(obj.clone()))?;
            if key_id.as_str() != unidpp_signatif::keyring::KeyId::of(&public).as_str() {
                return Err(format!(
                    "`key_id` `{}` does not match the declared public key",
                    key_id.as_str()
                ));
            }
            node.register(RegisteredKey { key_id, public });
        }
    }
    Ok(node)
}

pub fn edge_to_value(c: &DelegationCredential) -> Value {
    let mut m = Map::new();
    m.insert("parent".into(), json!(c.parent.to_string()));
    m.insert("child".into(), json!(c.child.to_string()));
    // scope round-trips via serde (LayerConstraint / Interval).
    let scope = serde_json::to_value(&c.scope).map_err(|e| e.to_string());
    m.insert("scope".into(), scope.unwrap_or(Value::Null));
    m.insert(
        "signatures".into(),
        Value::Array(c.signatures.iter().map(slot_to_value).collect()),
    );
    Value::Object(m)
}

pub fn edge_from_value(v: &Value) -> Result<DelegationCredential, String> {
    let obj = v.as_object().ok_or("edge must be an object")?;
    let parent = NodeId::new(
        obj.get("parent")
            .and_then(Value::as_str)
            .ok_or("`parent` is required")?,
    )
    .map_err(|e| format!("`parent`: {e}"))?;
    let child = NodeId::new(
        obj.get("child")
            .and_then(Value::as_str)
            .ok_or("`child` is required")?,
    )
    .map_err(|e| format!("`child`: {e}"))?;
    let scope: unidpp_signatif::scope::DelegationScope =
        serde_json::from_value(obj.get("scope").cloned().ok_or("`scope` is required")?)
            .map_err(|e| format!("`scope`: {e}"))?;
    let signatures = obj
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or("`signatures` array is required")?;
    let signatures = signatures
        .iter()
        .map(slot_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DelegationCredential {
        parent,
        child,
        scope,
        signatures,
    })
}

// ============================================================================
// Trust list entries + master list witnesses + entries
// ============================================================================

#[derive(Debug, Clone)]
pub struct TrustListEntryRecord {
    pub node: NodeId,
    pub not_before: Timestamp,
    pub superseded_at: Option<Timestamp>,
}

impl TrustListEntryRecord {
    pub fn in_force_at(&self, t: Timestamp) -> bool {
        t >= self.not_before && self.superseded_at.map_or(true, |s| t < s)
    }
}

pub fn trust_entry_to_value(e: &TrustListEntryRecord, at: Timestamp) -> Value {
    json!({
        "node": e.node.to_string(),
        "not_before": ts_string(&e.not_before),
        "superseded_at": e.superseded_at.map(|t| ts_string(&t)),
        "in_force_at_as_of": e.in_force_at(at),
    })
}

pub fn trust_entry_from_value(v: &Value) -> Result<TrustListEntryRecord, String> {
    let obj = v.as_object().ok_or("trust-list entry must be an object")?;
    let node = NodeId::new(
        obj.get("node")
            .and_then(Value::as_str)
            .ok_or("`node` is required")?,
    )
    .map_err(|e| format!("`node`: {e}"))?;
    let not_before_raw = obj
        .get("not_before")
        .and_then(Value::as_str)
        .ok_or("`not_before` (RFC 3339) is required")?;
    let not_before = ts_parse(not_before_raw)?;
    let superseded_at = match obj.get("superseded_at") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(ts_parse(s)?),
        Some(_) => return Err("`superseded_at` must be an RFC 3339 string or null".into()),
    };
    Ok(TrustListEntryRecord {
        node,
        not_before,
        superseded_at,
    })
}

/// Apply `entry` to a signatif TrustList (`not_before` inserts,
/// `superseded_at` withdraws). The TrustList holds raw `Timestamp`s
/// already.
pub fn apply_entry(list: &mut TrustList, entry: &TrustListEntryRecord) {
    list.entries
        .entry(entry.node.clone())
        .and_modify(|e| {
            if e.not_before != entry.not_before {
                e.not_before = entry.not_before;
            }
            e.superseded_at = entry.superseded_at;
        })
        .or_insert(unidpp_signatif::graph::TrustListEntry {
            node: entry.node.clone(),
            not_before: entry.not_before,
            superseded_at: entry.superseded_at,
        });
}

pub fn witness_attestation_to_value(w: &WitnessAttestation) -> Value {
    json!({
        "witness": w.witness.to_string(),
        "at": ts_string(&w.at),
        "slot": slot_to_value(&w.slot),
    })
}

pub fn witness_attestation_from_value(v: &Value) -> Result<WitnessAttestation, String> {
    let obj = v
        .as_object()
        .ok_or("witness attestation must be an object")?;
    let witness = NodeId::new(
        obj.get("witness")
            .and_then(Value::as_str)
            .ok_or("`witness` is required")?,
    )
    .map_err(|e| format!("`witness`: {e}"))?;
    let at = ts_parse(
        obj.get("at")
            .and_then(Value::as_str)
            .ok_or("`at` (RFC 3339) is required")?,
    )?;
    let slot = slot_from_value(obj.get("slot").ok_or("`slot` is required")?)?;
    Ok(WitnessAttestation { witness, at, slot })
}

pub fn master_entry_to_value(e: &MasterListEntry) -> Value {
    json!({
        "node": e.node.to_string(),
        "attestations": e.attestations.iter().map(witness_attestation_to_value).collect::<Vec<_>>(),
    })
}

pub fn master_entry_from_value(v: &Value) -> Result<MasterListEntry, String> {
    let obj = v.as_object().ok_or("master-list entry must be an object")?;
    let node = NodeId::new(
        obj.get("node")
            .and_then(Value::as_str)
            .ok_or("`node` is required")?,
    )
    .map_err(|e| format!("`node`: {e}"))?;
    let attestations = obj
        .get("attestations")
        .and_then(Value::as_array)
        .ok_or("`attestations` array is required")?;
    let attestations = attestations
        .iter()
        .map(witness_attestation_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MasterListEntry { node, attestations })
}

pub fn witnesses_to_value(master: &MasterList) -> Value {
    let mut out = Vec::new();
    for (node, key) in master.witnesses.iter() {
        out.push(json!({
            "node": node.to_string(),
            "suite": key.suite().to_string(),
            "key_id": unidpp_signatif::keyring::KeyId::of(key).to_string(),
            "public": hex_encode(key.as_bytes()),
            "public_len": key.as_bytes().len(),
        }));
    }
    Value::Array(out)
}

pub fn witnesses_from_value(v: &Value) -> Result<Vec<(NodeId, PublicKey)>, String> {
    let arr = v.as_array().ok_or("`witnesses` must be an array")?;
    let mut out = Vec::with_capacity(arr.len());
    for w in arr {
        let obj = w.as_object().ok_or("witness must be an object")?;
        let node = NodeId::new(
            obj.get("node")
                .and_then(Value::as_str)
                .ok_or("`node` is required")?,
        )
        .map_err(|e| format!("`node`: {e}"))?;
        let public = public_from_value(&Value::Object(obj.clone()))?;
        out.push((node, public));
    }
    Ok(out)
}

// ============================================================================
// Sanity checks (subject kind/label round trip + key derivation)
// ============================================================================

/// Convert a hex raw public key to a signatif PublicKey via the
/// `PublicKey::from_bytes` path (the safe one; the serde path is
/// asymmetric — see module docstring).
pub fn public_from_hex(suite_token: &str, hex: &str) -> Result<PublicKey, String> {
    let bytes = hex_decode(hex)?;
    let parsed = PublicKey::from_bytes(&bytes).map_err(|e| e.to_string())?;
    if parsed
        .suite()
        .to_string()
        .to_ascii_lowercase()
        .replace('-', "")
        != suite_token.to_ascii_lowercase().replace('-', "")
    {
        return Err(format!(
            "suite mismatch: declared `{suite_token}`, bytes are `{}`",
            parsed.suite()
        ));
    }
    Ok(parsed)
}

/// Build the live per-attestation verification verdicts for a master-
/// list entry. `verified = true` requires the slot to verify in the
/// `SigningDomain::MasterListWitness` domain against the registered
/// witness key.
pub fn attestations_verified(
    entry: &MasterListEntry,
    witnesses: &std::collections::BTreeMap<NodeId, PublicKey>,
) -> Vec<bool> {
    entry
        .attestations
        .iter()
        .map(|att| match witnesses.get(&att.witness) {
            Some(key) => att
                .slot
                .verify(
                    SigningDomain::MasterListWitness,
                    &WitnessAttestation::canonical_bytes(&entry.node, att.at),
                    key,
                )
                .is_ok(),
            None => false,
        })
        .collect()
}

/// Live quorate check: count distinct verifying witnesses; threshold
/// reached = quorate.
pub fn master_entry_quorate(
    entry: &MasterListEntry,
    witnesses: &std::collections::BTreeMap<NodeId, PublicKey>,
    m: usize,
) -> bool {
    let verified = attestations_verified(entry, witnesses);
    let mut distinct = BTreeSet::new();
    for (i, ok) in verified.iter().enumerate() {
        if *ok {
            distinct.insert(entry.attestations[i].witness.clone());
        }
    }
    distinct.len() >= m
}

/// Map signatif's [`SignatifError`] to a (status, message) pair the
/// API layer can render.
pub fn map_signatif_error(e: SignatifError) -> (u16, String) {
    match e {
        SignatifError::Validation(m) => (400, format!("validation: {m}")),
        SignatifError::ScopeViolation(m) => (400, format!("scope violation: {m}")),
        SignatifError::Crypto(m) => (400, format!("cryptographic: {m}")),
        SignatifError::SuiteDeferred { suite, detail } => {
            (400, format!("suite `{suite}` is deferred: {detail}"))
        }
        SignatifError::NoTrustPath { key_id } => (404, format!("no trust path to `{key_id}`")),
        SignatifError::ScopeExcluded { key_id, detail } => (
            400,
            format!("path to `{key_id}` excludes the request: {detail}"),
        ),
        SignatifError::CredentialSignatureInvalid { parent, child } => (
            400,
            format!("delegation credential {parent} → {child} failed signature verification"),
        ),
        SignatifError::Unknown { kind, id } => (404, format!("unknown {kind} `{id}`")),
        SignatifError::Trust(m) => (400, format!("trust anchoring: {m}")),
        SignatifError::Transparency(m) => (400, format!("transparency: {m}")),
        SignatifError::QuorumRequired { subject } => (
            422,
            format!("retroactive distrust of `{subject}` requires a quorate attestation"),
        ),
        SignatifError::ScopeConditionFailed { condition } => {
            (400, format!("scope condition failed: `{condition}`"))
        }
        SignatifError::Unsupported { suite, detail } => (
            400,
            format!("suite `{suite}` is unsupported in this build: {detail}"),
        ),
    }
}

// ============================================================================
// Helpers used by tests
// ============================================================================

/// Public-key fingerprint helper — only used by tests to compare keys
/// across reconstructions without comparing the raw `PublicKey` (the
/// Display impl hashes).
pub fn keypair_public_hex(key: &KeyPair) -> String {
    hex_encode(key.public().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        ts_parse(s).unwrap()
    }

    #[test]
    fn public_key_round_trip_uses_from_bytes_path() {
        let k = KeyPair::seeded(Suite::Ed25519, b"pub-test").unwrap();
        let v = public_to_value(k.public());
        assert_eq!(v["suite"], "ed25519");
        assert_eq!(v["public_len"], 32);
        let back = public_from_value(&v).unwrap();
        assert_eq!(back, *k.public());
    }

    #[test]
    fn public_key_suite_mismatch_rejected() {
        let k = KeyPair::seeded(Suite::Ed25519, b"mismatch").unwrap();
        let v = public_to_value(k.public());
        let mut bad = v.clone();
        bad["suite"] = json!("ecdsa-p256");
        assert!(public_from_value(&bad).is_err());
    }

    #[test]
    fn slot_to_from_value_round_trip() {
        let k = KeyPair::seeded(Suite::Ed25519, b"slot").unwrap();
        let s = SignatureSlot::sign(&k, SigningDomain::Delegation, b"x").unwrap();
        let v = slot_to_value(&s);
        assert!(!v["signature"].as_str().unwrap().is_empty());
        let back = slot_from_value(&v).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn revoked_subject_kind_round_trip() {
        let k = KeyId::new("k-abcdef0123456789").unwrap();
        let s = RevokedSubject::Key(k.clone());
        let v = revoked_subject_to_value(&s);
        assert_eq!(v["kind"], "key");
        let back = revoked_subject_from_value(&v).unwrap();
        assert_eq!(back, s);
        let label = format!("key:{}", k.as_str());
        assert_eq!(revoked_subject_from_label(&label).unwrap(), s);
    }

    #[test]
    fn revoked_subject_label_passport() {
        let p = unidpp_model::PassportId::new("urn:unidpp:passport:b0").unwrap();
        let s = RevokedSubject::Passport(p.clone());
        let label = format!("passport:{}", p.as_str());
        assert_eq!(revoked_subject_from_label(&label).unwrap(), s);
    }

    #[test]
    fn reason_round_trip_all_variants() {
        let cases = vec![
            RevocationReason::KeyCompromise {
                after: ts("2026-01-01T00:00:00Z"),
            },
            RevocationReason::Cessation,
            RevocationReason::Supersession {
                by: NodeId::new("next").unwrap(),
            },
            RevocationReason::AffiliationChange,
            RevocationReason::Misissuance,
            RevocationReason::FraudulentIssuance,
            RevocationReason::AuthorityCompromised {
                detected_at: ts("2026-02-01T00:00:00Z"),
            },
        ];
        for r in &cases {
            let v = reason_to_value(r);
            assert_eq!(v["token"].as_str().unwrap(), r.token());
            assert_eq!(v["retroactive"].as_bool().unwrap(), r.is_retroactive());
            let back = reason_from_value(&v).unwrap();
            assert_eq!(&back, r);
        }
    }

    #[test]
    fn interval_value_bounded_and_open() {
        let bounded = interval_to_value(
            &unidpp_model::Interval::between(
                ts("2026-01-01T00:00:00Z"),
                ts("2026-02-01T00:00:00Z"),
            )
            .unwrap(),
        );
        assert_eq!(bounded["open"], false);
        let back = interval_from_value(&bounded).unwrap();
        assert_eq!(back.from, ts("2026-01-01T00:00:00Z"));
        assert_eq!(back.to, Some(ts("2026-02-01T00:00:00Z")));

        let open = interval_to_value(&unidpp_model::Interval::starting(ts(
            "2026-01-01T00:00:00Z",
        )));
        assert_eq!(open["open"], true);
        let back = interval_from_value(&open).unwrap();
        assert_eq!(back.from, ts("2026-01-01T00:00:00Z"));
        assert_eq!(back.to, None);
    }

    #[test]
    fn interval_inverted_window_rejected() {
        let bad = json!({"start": "2026-02-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"});
        assert!(interval_from_value(&bad).is_err());
    }

    #[test]
    fn node_round_trip_root_and_threshold_group() {
        let root = DelegationNode::new(NodeId::new("r").unwrap(), NodeKind::Root);
        let v = node_to_value(&root);
        assert_eq!(v["kind"], "root");
        let back = node_from_value(&v).unwrap();
        assert_eq!(back.id, root.id);
        assert_eq!(back.kind, root.kind);

        let tg = DelegationNode::new(
            NodeId::new("g").unwrap(),
            NodeKind::ThresholdGroup {
                threshold: 2,
                members: BTreeSet::from([NodeId::new("m1").unwrap(), NodeId::new("m2").unwrap()]),
            },
        );
        let v = node_to_value(&tg);
        let back = node_from_value(&v).unwrap();
        assert_eq!(back.kind, tg.kind);
    }

    #[test]
    fn edge_round_trip_via_wire_value() {
        let parent = NodeId::new("p").unwrap();
        let child = NodeId::new("c").unwrap();
        let scope = unidpp_signatif::scope::DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"]);
        let key = KeyPair::seeded(Suite::Ed25519, b"edge").unwrap();
        let cred = DelegationCredential::mint_sign(&parent, &child, scope.clone(), &key).unwrap();
        let v = edge_to_value(&cred);
        let back = edge_from_value(&v).unwrap();
        assert_eq!(back, cred);
    }

    #[test]
    fn master_witnesses_and_entries_round_trip() {
        let m = MasterList::new(
            2,
            std::collections::BTreeMap::from([
                (
                    NodeId::new("w1").unwrap(),
                    *KeyPair::seeded(Suite::Ed25519, b"w1").unwrap().public(),
                ),
                (
                    NodeId::new("w2").unwrap(),
                    *KeyPair::seeded(Suite::EcdsaP256, b"w2").unwrap().public(),
                ),
            ]),
        );
        let v = witnesses_to_value(&m);
        assert_eq!(v.as_array().unwrap().len(), 2);
        let back = witnesses_from_value(&v).unwrap();
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn hex_round_trip_through_public() {
        let k = KeyPair::seeded(Suite::EcdsaP256, b"hex").unwrap();
        let hex = keypair_public_hex(&k);
        assert_eq!(hex.len(), 130); // 65 bytes
        let back = public_from_hex("ecdsa-p256", &hex).unwrap();
        assert_eq!(back, *k.public());
    }
}
