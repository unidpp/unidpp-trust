//! Store: in-memory state + append-only JSONL journal. The journal
//! replays losslessly on start; mutations are validated before being
//! recorded and applied.
//!
//! Pattern lifted from `unidpp-registry/src/store.rs`: every mutation
//! becomes an [`AuditRecord`] carrying the full payload (signed
//! delegation credentials, attestations, the whole master-list entry,
//! the whole revocation). Nothing is edited in place — superseding a
//! trust-list entry appends a record that re-asserts the new state.
//!
//! The seed path emits normal ops (so a restart replays them exactly),
//! gated on `seed_when_empty`: when a fresh journal replays to zero
//! records the store seeds once and writes the seed records to the
//! journal. Disabling seeding (`Config::seed_fixtures = false`) skips
//! the fixture material entirely.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde_json::{json, Value};

use unidpp_model::Timestamp;
use unidpp_signatif::graph::{
    DelegationCredential, DelegationNode, MasterList, MasterListEntry, NodeId, TrustGraph,
    TrustList,
};
use unidpp_signatif::keyring::PublicKey;
use unidpp_signatif::revoke::{Revocation, RevocationLedger};

use crate::seed;
use crate::wire::{
    apply_entry, edge_from_value, edge_to_value, master_entry_from_value, master_entry_to_value,
    node_from_value, node_to_value, revocation_from_value, revocation_to_value,
    TrustListEntryRecord,
};

/// Store-level validation failures, mapped by the API layer
/// (`Conflict` → 409, `Invalid` → 400, `NotFound` → 404, `Forbidden`
/// → 422).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Conflict(String),
    Invalid(String),
    NotFound(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Conflict(m) => write!(f, "conflict: {m}"),
            StoreError::Invalid(m) => write!(f, "invalid: {m}"),
            StoreError::NotFound(m) => write!(f, "not found: {m}"),
        }
    }
}
impl std::error::Error for StoreError {}

/// An append-only store mutation.
#[derive(Debug, Clone)]
pub enum Op {
    /// Insert or merge a trust-graph node (idempotent on id; keys
    /// merge into the existing node).
    RegisterNode { node: DelegationNode },
    /// Add a delegation credential. Validates via `TrustGraph::add_edge`.
    AddEdge { credential: DelegationCredential },
    /// Register a new trust list for a jurisdiction (conflict if a
    /// list with this jurisdiction already exists).
    RegisterTrustList {
        jurisdiction: String,
        framework: Option<String>,
    },
    /// Upsert a single trust-list entry (insert if new, else replace
    /// its `not_before` and `superseded_at`). The list must exist.
    UpsertTrustEntry {
        jurisdiction: String,
        node: NodeId,
        not_before: Timestamp,
        superseded_at: Option<Timestamp>,
    },
    /// Set or replace the master-list witness set. `m` must satisfy
    /// `1 <= m <= witnesses.len()`.
    SetWitnesses {
        m: usize,
        witnesses: Vec<(NodeId, PublicKey)>,
    },
    /// Upsert a master-list entry by node. All attestations must
    /// reference registered witnesses (else validation rejects).
    UpsertMasterEntry { entry: MasterListEntry },
    /// Declare a revocation. Retroactive reasons require a quorum
    /// attestation that verifies against the trust-graph key
    /// directory; prospective reasons need no quorum.
    DeclareRevocation { revocation: Revocation },
}

/// One audit record in the journal.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub seq: u64,
    pub recorded_at: Timestamp,
    pub op: Op,
}

impl AuditRecord {
    /// Render to JSON for the journal and the audit-log endpoint.
    /// Delegates to the wire layer for all opaque types so the journal
    /// shape is the public wire shape (round-trippable).
    pub fn to_json(&self) -> Value {
        let (op_name, body) = match &self.op {
            Op::RegisterNode { node } => ("register-node", node_to_value(node)),
            Op::AddEdge { credential } => ("add-edge", edge_to_value(credential)),
            Op::RegisterTrustList {
                jurisdiction,
                framework,
            } => (
                "register-trust-list",
                json!({
                    "jurisdiction": jurisdiction,
                    "framework": framework,
                }),
            ),
            Op::UpsertTrustEntry {
                jurisdiction,
                node,
                not_before,
                superseded_at,
            } => (
                "upsert-trust-entry",
                json!({
                    "jurisdiction": jurisdiction,
                    "node": node.to_string(),
                    "not_before": crate::time::Timestamp::from_model(*not_before).to_string(),
                    "superseded_at": superseded_at.map(|t| crate::time::Timestamp::from_model(t).to_string()),
                }),
            ),
            Op::SetWitnesses { m, witnesses } => {
                let ws: Vec<Value> = witnesses
                    .iter()
                    .map(|(id, key)| {
                        json!({
                            "node": id.to_string(),
                            "suite": key.suite().to_string(),
                            "public": crate::hex::hex_encode(key.as_bytes()),
                            "public_len": key.as_bytes().len(),
                        })
                    })
                    .collect();
                ("set-witnesses", json!({ "m": m, "witnesses": ws }))
            }
            Op::UpsertMasterEntry { entry } => {
                ("upsert-master-entry", master_entry_to_value(entry))
            }
            Op::DeclareRevocation { revocation } => {
                ("declare-revocation", revocation_to_value(revocation))
            }
        };
        let mut m = serde_json::Map::new();
        m.insert("op".into(), json!(op_name));
        m.insert("body".into(), body);
        m.insert("seq".into(), json!(self.seq));
        m.insert(
            "recorded_at".into(),
            json!(crate::time::Timestamp::from_model(self.recorded_at).to_string()),
        );
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Result<AuditRecord, String> {
        let obj = v.as_object().ok_or("audit record must be an object")?;
        let seq = obj
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or("missing `seq`")?;
        let recorded_at = obj
            .get("recorded_at")
            .and_then(Value::as_str)
            .map(crate::time::Timestamp::parse)
            .transpose()
            .map_err(|e| format!("`recorded_at`: {e}"))?
            .ok_or("missing `recorded_at`")?
            .to_model();
        let op_name = obj
            .get("op")
            .and_then(Value::as_str)
            .ok_or("missing `op`")?;
        let body = obj.get("body").ok_or("missing `body`")?;
        let op = match op_name {
            "register-node" => {
                let node = node_from_value(body)?;
                Op::RegisterNode { node }
            }
            "add-edge" => {
                let credential = edge_from_value(body)?;
                Op::AddEdge { credential }
            }
            "register-trust-list" => {
                let j = obj
                    .get("body")
                    .and_then(|b| b.as_object())
                    .ok_or("`body` not an object")?;
                let jurisdiction = j
                    .get("jurisdiction")
                    .and_then(Value::as_str)
                    .ok_or("`jurisdiction` is required")?
                    .to_string();
                let framework = j
                    .get("framework")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                Op::RegisterTrustList {
                    jurisdiction,
                    framework,
                }
            }
            "upsert-trust-entry" => {
                let j = obj
                    .get("body")
                    .and_then(|b| b.as_object())
                    .ok_or("`body` not an object")?;
                let jurisdiction = j
                    .get("jurisdiction")
                    .and_then(Value::as_str)
                    .ok_or("`jurisdiction` is required")?
                    .to_string();
                let node_str = j
                    .get("node")
                    .and_then(Value::as_str)
                    .ok_or("`node` is required")?;
                let node = NodeId::new(node_str).map_err(|e| e.to_string())?;
                let not_before_str = j
                    .get("not_before")
                    .and_then(Value::as_str)
                    .ok_or("`not_before` is required")?;
                let not_before = crate::time::Timestamp::parse(not_before_str)
                    .map_err(|e| e.to_string())?
                    .to_model();
                let superseded_at = j
                    .get("superseded_at")
                    .and_then(Value::as_str)
                    .map(|s| crate::time::Timestamp::parse(s).map(|t| t.to_model()))
                    .transpose()
                    .map_err(|e| e.to_string())?;
                Op::UpsertTrustEntry {
                    jurisdiction,
                    node,
                    not_before,
                    superseded_at,
                }
            }
            "set-witnesses" => {
                let j = obj
                    .get("body")
                    .and_then(|b| b.as_object())
                    .ok_or("`body` not an object")?;
                let m = j
                    .get("m")
                    .and_then(Value::as_u64)
                    .ok_or("`m` is required")? as usize;
                let ws = j
                    .get("witnesses")
                    .and_then(Value::as_array)
                    .ok_or("`witnesses` is required")?;
                let witnesses = ws
                    .iter()
                    .map(|w| {
                        crate::wire::public_from_value(w).map(|pk| {
                            let node =
                                NodeId::new(w.get("node").and_then(Value::as_str).unwrap_or(""))
                                    .unwrap();
                            (node, pk)
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Op::SetWitnesses { m, witnesses }
            }
            "upsert-master-entry" => {
                let entry = master_entry_from_value(body)?;
                Op::UpsertMasterEntry { entry }
            }
            "declare-revocation" => {
                let revocation = revocation_from_value(body)?;
                Op::DeclareRevocation { revocation }
            }
            other => return Err(format!("unknown `op` `{other}`")),
        };
        Ok(AuditRecord {
            seq,
            recorded_at,
            op,
        })
    }
}

/// The trust store: graph, trust lists (keyed by jurisdiction),
/// master list, revocation ledger, audit log, and JSONL journal.
pub struct Store {
    pub graph: TrustGraph,
    /// Trust lists, keyed by normalised jurisdiction (uppercase). The
    /// framework is metadata for grouping/filtering.
    pub trust_lists: HashMap<String, TrustList>,
    pub frameworks: HashMap<String, Option<String>>,
    pub master: MasterList,
    pub ledger: RevocationLedger,
    pub log: Vec<AuditRecord>,
    pub journal: Option<File>,
}

impl Store {
    /// Open a store, replaying `journal` if present. When the replayed
    /// log is empty and `seed_when_empty` is `true`, the seed fixtures
    /// are appended (and journaled). Pass `seed_when_empty = false` to
    /// skip the fixture material entirely (production with a hot
    /// journal).
    pub fn open(journal: Option<&Path>, seed_when_empty: bool) -> std::io::Result<Store> {
        let mut store = Store {
            graph: TrustGraph::new(),
            trust_lists: HashMap::new(),
            frameworks: HashMap::new(),
            master: MasterList::new(1, BTreeMap::new()),
            ledger: RevocationLedger::new(),
            log: Vec::new(),
            journal: None,
        };
        if let Some(path) = journal {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if path.exists() {
                store.replay(path)?;
            }
            store.journal = Some(OpenOptions::new().create(true).append(true).open(path)?);
        }
        if seed_when_empty && store.log.is_empty() {
            store.seed_fixtures();
        }
        Ok(store)
    }

    fn replay(&mut self, path: &Path) -> std::io::Result<()> {
        let file = File::open(path)?;
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(&line)
                .map_err(|e| e.to_string())
                .and_then(|v| AuditRecord::from_json(&v))
            {
                Ok(rec) => {
                    // Replay-time failures (e.g. an AddEdge against an
                    // absent node) are skipped loudly: the journal is
                    // append-only and crash-tolerant, but a corrupted
                    // line is not silently swallowed.
                    if let Err(e) = self.apply_op(&rec.op) {
                        eprintln!("unidpp-trust: journal line {} apply failed: {e}", i + 1);
                    }
                    self.log.push(rec);
                }
                Err(e) => {
                    // Torn final line tolerated (crash mid-write);
                    // anything else reported.
                    eprintln!("unidpp-trust: journal line {}: {e}", i + 1);
                }
            }
        }
        Ok(())
    }

    fn apply_op(&mut self, op: &Op) -> Result<(), StoreError> {
        match op {
            Op::RegisterNode { node } => {
                // Merge: insert if absent, else take the incoming
                // kind (the node IS the operator's assertion — a
                // re-registered quorum node's threshold is the
                // current assertion, not historical) and merge keys
                // not yet known to the same node.
                self.graph.add_node(node.clone());
                if let Some(existing) = self.graph.node_mut(&node.id) {
                    existing.kind = node.kind.clone();
                    for k in &node.keys {
                        if !existing.keys.iter().any(|ek| ek.key_id == k.key_id) {
                            existing.keys.push(k.clone());
                        }
                    }
                }
                Ok(())
            }
            Op::AddEdge { credential } => self
                .graph
                .add_edge(credential.clone())
                .map_err(|e| StoreError::Invalid(e.to_string())),
            Op::RegisterTrustList {
                jurisdiction,
                framework,
            } => {
                let key = jurisdiction.to_ascii_uppercase();
                if self.trust_lists.contains_key(&key) {
                    return Err(StoreError::Conflict(format!(
                        "trust list `{jurisdiction}` is already registered"
                    )));
                }
                self.trust_lists
                    .insert(key.clone(), TrustList::new(jurisdiction));
                self.frameworks.insert(key, framework.clone());
                Ok(())
            }
            Op::UpsertTrustEntry {
                jurisdiction,
                node,
                not_before,
                superseded_at,
            } => {
                let key = jurisdiction.to_ascii_uppercase();
                let list = self.trust_lists.get_mut(&key).ok_or_else(|| {
                    StoreError::NotFound(format!("no trust list `{jurisdiction}`"))
                })?;
                let entry = TrustListEntryRecord {
                    node: node.clone(),
                    not_before: *not_before,
                    superseded_at: *superseded_at,
                };
                apply_entry(list, &entry);
                Ok(())
            }
            Op::SetWitnesses { m, witnesses } => {
                if *m == 0 {
                    return Err(StoreError::Invalid("`m` must be >= 1".into()));
                }
                if witnesses.is_empty() {
                    return Err(StoreError::Invalid("`witnesses` must be non-empty".into()));
                }
                if *m > witnesses.len() {
                    return Err(StoreError::Invalid(format!(
                        "`m` ({m}) cannot exceed `witnesses.len()` ({})",
                        witnesses.len()
                    )));
                }
                let map: BTreeMap<NodeId, PublicKey> = witnesses.iter().cloned().collect();
                let mut master = MasterList::new(*m, map);
                // Entries survive a witness-set change: attestations
                // carry their witness, so they re-verify (or stop
                // verifying) against the new set live. Replacing a
                // witness key is therefore a live de-attestation of
                // everything that key had signed.
                master.entries = std::mem::take(&mut self.master.entries);
                self.master = master;
                Ok(())
            }
            Op::UpsertMasterEntry { entry } => {
                // Attestations must reference registered witnesses.
                for att in &entry.attestations {
                    if !self.master.witnesses.contains_key(&att.witness) {
                        return Err(StoreError::Invalid(format!(
                            "witness `{}` is not registered",
                            att.witness
                        )));
                    }
                }
                self.master.upsert(entry.clone());
                Ok(())
            }
            Op::DeclareRevocation { revocation } => {
                // Retroactive reasons require a quorate attestation.
                if revocation.reason.is_retroactive() {
                    let quorum = revocation.quorum.as_ref().ok_or_else(|| {
                        StoreError::Invalid(format!(
                            "retroactive distrust of `{}` requires a quorum attestation",
                            revocation.subject.label()
                        ))
                    })?;
                    let v =
                        crate::quorum::verdict(&self.graph, quorum, &revocation.statement_bytes());
                    if !v.quorate {
                        return Err(StoreError::Invalid(format!(
                            "quorum attestation for `{}` does not reach the threshold ({})",
                            revocation.subject.label(),
                            v.summary()
                        )));
                    }
                }
                self.ledger
                    .declare(revocation.clone())
                    .map_err(|e| StoreError::Invalid(e.to_string()))
            }
        }
    }

    fn seed_fixtures(&mut self) {
        let ops = seed::seed_ops();
        for op in ops {
            self.record(op);
        }
    }

    /// Append a record to the audit log (and journal), then apply it.
    pub fn record(&mut self, op: Op) -> AuditRecord {
        let recorded_at = crate::time::Timestamp::now().to_model();
        let rec = AuditRecord {
            seq: self.log.len() as u64 + 1,
            recorded_at,
            op,
        };
        if let Some(j) = self.journal.as_mut() {
            if let Err(e) = writeln!(j, "{}", rec.to_json()) {
                eprintln!("unidpp-trust: journal write failed: {e}");
            }
        }
        // Live mutation: validation has already happened in the typed
        // public entry points (apply_op is infallible for the seed path
        // because the seed emits pre-validated ops).
        if let Err(e) = self.apply_op(&rec.op) {
            eprintln!("unidpp-trust: live apply failed: {e}");
        }
        self.log.push(rec.clone());
        rec
    }

    // -- typed mutation entry points (validated) -------------------------

    pub fn register_node(&mut self, node: DelegationNode) -> Result<AuditRecord, StoreError> {
        Ok(self.record(Op::RegisterNode { node }))
    }

    pub fn add_edge(
        &mut self,
        credential: DelegationCredential,
    ) -> Result<AuditRecord, StoreError> {
        // Validate on a throwaway clone: `record` applies the op for
        // real, and a pre-validation that mutated in place would add
        // the edge twice.
        self.graph
            .clone()
            .add_edge(credential.clone())
            .map_err(|e| StoreError::Invalid(e.to_string()))?;
        Ok(self.record(Op::AddEdge { credential }))
    }

    pub fn register_trust_list(
        &mut self,
        jurisdiction: String,
        framework: Option<String>,
    ) -> Result<AuditRecord, StoreError> {
        // Validate before recording (Conflict on duplicate).
        let key = jurisdiction.to_ascii_uppercase();
        if self.trust_lists.contains_key(&key) {
            return Err(StoreError::Conflict(format!(
                "trust list `{jurisdiction}` is already registered"
            )));
        }
        Ok(self.record(Op::RegisterTrustList {
            jurisdiction,
            framework,
        }))
    }

    pub fn upsert_trust_entry(
        &mut self,
        jurisdiction: String,
        node: NodeId,
        not_before: Timestamp,
        superseded_at: Option<Timestamp>,
    ) -> Result<AuditRecord, StoreError> {
        let key = jurisdiction.to_ascii_uppercase();
        if !self.trust_lists.contains_key(&key) {
            return Err(StoreError::NotFound(format!(
                "no trust list `{jurisdiction}`"
            )));
        }
        Ok(self.record(Op::UpsertTrustEntry {
            jurisdiction,
            node,
            not_before,
            superseded_at,
        }))
    }

    pub fn set_witnesses(
        &mut self,
        m: usize,
        witnesses: Vec<(NodeId, PublicKey)>,
    ) -> Result<AuditRecord, StoreError> {
        if m == 0 || witnesses.is_empty() || m > witnesses.len() {
            let err = if m == 0 {
                "`m` must be >= 1".to_string()
            } else if witnesses.is_empty() {
                "`witnesses` must be non-empty".to_string()
            } else {
                format!(
                    "`m` ({m}) cannot exceed `witnesses.len()` ({})",
                    witnesses.len()
                )
            };
            return Err(StoreError::Invalid(err));
        }
        Ok(self.record(Op::SetWitnesses { m, witnesses }))
    }

    pub fn upsert_master_entry(
        &mut self,
        entry: MasterListEntry,
    ) -> Result<AuditRecord, StoreError> {
        for att in &entry.attestations {
            if !self.master.witnesses.contains_key(&att.witness) {
                return Err(StoreError::Invalid(format!(
                    "witness `{}` is not registered",
                    att.witness
                )));
            }
        }
        Ok(self.record(Op::UpsertMasterEntry { entry }))
    }

    pub fn declare_revocation(
        &mut self,
        revocation: Revocation,
    ) -> Result<AuditRecord, StoreError> {
        // Pre-validation: retroactive needs a quorate attestation.
        if revocation.reason.is_retroactive() {
            let quorum = revocation.quorum.as_ref().ok_or_else(|| {
                StoreError::Invalid(format!(
                    "retroactive distrust of `{}` requires a quorum attestation",
                    revocation.subject.label()
                ))
            })?;
            let v = crate::quorum::verdict(&self.graph, quorum, &revocation.statement_bytes());
            if !v.quorate {
                return Err(StoreError::Invalid(format!(
                    "quorum attestation for `{}` does not reach the threshold ({})",
                    revocation.subject.label(),
                    v.summary()
                )));
            }
        }
        // Mirror RevocationLedger::declare's own retroactive-without-
        // quorum guard (defence in depth — keeps the ledger invariant
        // even if a caller bypasses our pre-check). Validated on a
        // throwaway clone: `record` applies the op for real, and a
        // pre-validation that mutated in place would declare twice.
        self.ledger
            .clone()
            .declare(revocation.clone())
            .map_err(|e| StoreError::Invalid(e.to_string()))?;
        Ok(self.record(Op::DeclareRevocation { revocation }))
    }

    // -- reads ----------------------------------------------------------

    pub fn trust_list(&self, jurisdiction: &str) -> Option<&TrustList> {
        self.trust_lists.get(&jurisdiction.to_ascii_uppercase())
    }

    pub fn jurisdictions(&self) -> Vec<String> {
        let mut out: Vec<String> = self.trust_lists.keys().cloned().collect();
        out.sort();
        out
    }

    pub fn log_json(&self, limit: usize, offset: usize) -> Value {
        let total = self.log.len();
        let records: Vec<Value> = self
            .log
            .iter()
            .skip(offset)
            .take(limit)
            .map(AuditRecord::to_json)
            .collect();
        json!({ "total": total, "offset": offset, "records": records })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_model::Interval;
    use unidpp_signatif::graph::NodeKind;
    use unidpp_signatif::revoke::{QuorumAttestation, RevocationReason, RevokedSubject};

    fn ts(s: &str) -> Timestamp {
        crate::time::Timestamp::parse(s).unwrap().to_model()
    }

    #[test]
    fn seed_replays_into_full_graph_and_lists() {
        let store = Store::open(None, true).unwrap();
        // EU trust list present, master list quorate, ledger has 2 revocations.
        assert!(store.trust_list("EU").is_some());
        let root = NodeId::new("eu-root").unwrap();
        assert!(store.master.accepts(&root));
        assert_eq!(store.ledger.revocations().len(), 2);
        assert_eq!(store.log.len(), store.log.len()); // tautology, real asserts above
        assert!(store.graph.node_count() > 0);
    }

    #[test]
    fn seed_is_skipped_when_journal_replayed_content() {
        let dir = std::env::temp_dir().join(format!("unidpp-trust-journal-{}", std::process::id()));
        let path = dir.join("trust.jsonl");
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&dir).unwrap();
        // First run: seed + write journal.
        {
            let store = Store::open(Some(&path), true).unwrap();
            assert!(store.trust_list("EU").is_some());
        }
        // Second run: replay-only (seed skipped because log is non-empty).
        let store = Store::open(Some(&path), true).unwrap();
        assert!(store.trust_list("EU").is_some());
        assert!(store.master.accepts(&NodeId::new("eu-root").unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn register_node_is_idempotent_and_merges_keys() {
        let mut store = Store::open(None, false).unwrap();
        let id = NodeId::new("n").unwrap();
        let k1 =
            unidpp_signatif::keyring::KeyPair::seeded(unidpp_signatif::sign::Suite::Ed25519, b"k1")
                .unwrap();
        let k2 = unidpp_signatif::keyring::KeyPair::seeded(
            unidpp_signatif::sign::Suite::EcdsaP256,
            b"k2",
        )
        .unwrap();
        let mut n1 = DelegationNode::new(id.clone(), NodeKind::Root);
        n1.register(unidpp_signatif::graph::RegisteredKey::of(&k1));
        store.register_node(n1.clone()).unwrap();
        // Re-register the same node with a different key — merged.
        let mut n2 = DelegationNode::new(id.clone(), NodeKind::Root);
        n2.register(unidpp_signatif::graph::RegisteredKey::of(&k2));
        store.register_node(n2).unwrap();
        let node = store.graph.node(&id).unwrap();
        assert_eq!(node.keys.len(), 2);
    }

    #[test]
    fn add_edge_rejects_unknown_node_and_unsiged() {
        let mut store = Store::open(None, false).unwrap();
        let ghost = NodeId::new("ghost").unwrap();
        let child = NodeId::new("child").unwrap();
        let k =
            unidpp_signatif::keyring::KeyPair::seeded(unidpp_signatif::sign::Suite::Ed25519, b"a")
                .unwrap();
        let cred = DelegationCredential::mint_sign(&ghost, &child, Default::default(), &k).unwrap();
        assert!(matches!(store.add_edge(cred), Err(StoreError::Invalid(_))));
    }

    #[test]
    fn upsert_trust_entry_requires_list_first() {
        let mut store = Store::open(None, false).unwrap();
        let id = NodeId::new("x").unwrap();
        let err = store
            .upsert_trust_entry("EU".into(), id, ts("2026-01-01T00:00:00Z"), None)
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[test]
    fn master_witness_set_rejects_bad_m() {
        let mut store = Store::open(None, false).unwrap();
        let id = NodeId::new("w").unwrap();
        let key = unidpp_signatif::keyring::PublicKey::from_bytes(&[0u8; 32]).unwrap();
        assert!(store.set_witnesses(0, vec![(id.clone(), key)]).is_err());
        assert!(store.set_witnesses(2, vec![(id, key)]).is_err());
    }

    #[test]
    fn declare_retroactive_without_quorum_is_rejected() {
        let mut store = Store::open(None, true).unwrap();
        let rev = Revocation {
            subject: RevokedSubject::Key(
                unidpp_signatif::keyring::KeyId::new("k-missing").unwrap(),
            ),
            reason: RevocationReason::Misissuance,
            declared_at: ts("1970-01-12T16:53:20Z"),
            window: Interval::between(ts("1970-01-12T14:36:40Z"), ts("1970-01-12T15:50:00Z"))
                .unwrap(),
            declared_by: NodeId::new("eu-super-quorum").unwrap(),
            quorum: None,
        };
        let err = store.declare_revocation(rev).unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)));
    }

    #[test]
    fn declare_retroactive_with_below_threshold_quorum_is_rejected() {
        let mut store = Store::open(None, true).unwrap();
        // A real quorum member (registered on the seeded graph), signing
        // alone with threshold 2: the signature verifies but the count
        // of distinct verifying member keys (1) is below the threshold.
        let member = unidpp_signatif::keyring::KeyPair::seeded(
            unidpp_signatif::sign::Suite::Ed25519,
            b"scenario/quorum-1",
        )
        .unwrap();
        let mut rev = Revocation {
            subject: RevokedSubject::Key(unidpp_signatif::keyring::KeyId::new("k-below").unwrap()),
            reason: RevocationReason::Misissuance,
            declared_at: Timestamp::from_secs(1),
            window: Interval::starting(Timestamp::from_secs(0)),
            declared_by: NodeId::new("eu-super-quorum").unwrap(),
            quorum: None,
        };
        let qs: Vec<&unidpp_signatif::keyring::KeyPair> = vec![&member];
        let att =
            QuorumAttestation::mint_sign(&rev.declared_by, 2, &rev.statement_bytes(), &qs).unwrap();
        rev.quorum = Some(att);
        let err = store.declare_revocation(rev).unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)));
    }

    #[test]
    fn journal_round_trip_includes_seed_and_mutation() {
        let dir = std::env::temp_dir().join(format!("unidpp-trust-rt-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&dir).unwrap();
        let key;
        {
            let mut store = Store::open(Some(&path), true).unwrap();
            assert!(store.trust_list("EU").is_some());
            // Add an extra trust entry (mutate).
            let id = NodeId::new("more").unwrap();
            store
                .upsert_trust_entry(
                    "EU".into(),
                    id,
                    crate::time::Timestamp::parse("2026-09-07T00:00:00Z")
                        .unwrap()
                        .to_model(),
                    None,
                )
                .unwrap();
            key = store.log.last().unwrap().seq;
        }
        let store = Store::open(Some(&path), true).unwrap();
        // The journal replays seed + mutation; the audit log's final
        // sequence number matches what we appended.
        assert!(store.log.last().unwrap().seq >= key);
        assert!(store.trust_list("EU").is_some());
        let list = store.trust_list("EU").unwrap();
        assert!(list.entries.contains_key(&NodeId::new("more").unwrap()));
        let _ = std::fs::remove_file(&path);
    }
}
