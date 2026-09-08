//! The quorum-ceremony operator binary: build a threshold-ceremony
//! quorum attestation for a retroactive revocation, from the shell.
//!
//! Retroactive distrust (misissuance, fraud, authority-compromised)
//! is an act of authority-over-authority — the trust service refuses
//! it without a quorate attestation. This binary runs the REAL
//! ceremony (SIGNATIF's [`RealCeremony`] behind its `confium`
//! feature: Feldman VSS, threshold Schnorr partials, one standard
//! Ed25519 group signature) over a revocation statement and emits the
//! exact HTTP bodies the service accepts:
//!
//! ```text
//! quorum-ceremony declare \
//!     --quorum e8-retro-quorum --threshold 2 \
//!     --member reg-cn-samr --member reg-jp-meti --member reg-eu-espr \
//!     --signer reg-cn-samr --signer reg-jp-meti \
//!     --subject-kind node --subject-id haichuan-cn \
//!     --reason misissuance \
//!     --window-start 2027-01-01T00:00:00Z --window-end 2030-06-01T00:00:00Z \
//!     --declared-at 2030-06-15T00:00:00Z \
//!     --out-dir ceremony/
//! ```
//!
//! `--out-dir` receives:
//!
//! - `quorum-node.json` — the `POST /nodes` body: the quorum node
//!   (a threshold group naming its members) pinning the ceremony's
//!   **group public key** as its registered key. Pinning is
//!   load-bearing: until the service's graph holds the group key, the
//!   attestation certifies nothing.
//! - `revocation.json` — the `POST /revocations` body, the quorum
//!   attestation carrying the combined group signature as its single
//!   slot.
//! - `ceremony.json` — the audit trail (group key + Feldman
//!   commitments, the qualifying set, the statement digest).
//!
//! A qualifying set of fewer than `--threshold` signers is refused by
//! the ceremony itself (exit 1, "quorum not met") — the refusal is
//! the cryptography, not a policy check. The ceremony seed derives
//! from the public quorum spec (see `RealCeremony`'s documented
//! limits): reproducible for rehearsals and demos, NOT a production
//! root ceremony — production derives groups from secret entropy or
//! a real DKG.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::json;
use unidpp_model::Timestamp;
use unidpp_signatif::confium::real::RealCeremony;
use unidpp_signatif::confium::{
    CeremonyCoordinator, CeremonyError, CeremonyKind, CeremonyStatement, QuorumSpec, SessionInit,
};
use unidpp_signatif::graph::{DelegationNode, NodeKind, RegisteredKey};
use unidpp_signatif::keyring::{KeyId, PublicKey};
use unidpp_signatif::revoke::{QuorumAttestation, Revocation, RevocationReason};
use unidpp_signatif::threshold::GroupKey;

use unidpp_trust::hex::{hex_decode, hex_encode};
use unidpp_trust::wire::{
    interval_from_value, interval_to_value, node_to_value, reason_from_value, reason_to_value,
    revocation_to_value, revoked_subject_from_value, revoked_subject_to_value,
};
use unidpp_trust::Timestamp as ServiceTimestamp;

const USAGE: &str = "\
unidpp-trust quorum-ceremony — threshold-ceremony quorum attestations

USAGE:
  quorum-ceremony declare --quorum <ID> --threshold <M> --member <ID>...
                          --signer <ID>... --subject-kind <key|node|passport>
                          --subject-id <ID> --reason <TOKEN> --window-start <TS>
                          [--window-end <TS>] --declared-at <TS> --out-dir <DIR>

  --reason tokens: misissuance | fraudulent-issuance | authority-compromised
    (authority-compromised also needs --detected-at <TS>;
     key-compromise/cessation/... are prospective — no quorum, use the API)

The ceremony runs over the revocation's canonical statement bytes in
the SIGNATIF Quorum signing domain. The group signature verifies as
standard Ed25519 under the group key; the service accepts it once the
quorum node (POST /nodes body in quorum-node.json) pins that key.";

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(text) => {
            println!("{text}");
            std::process::ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("quorum-ceremony: {message}\n\n{USAGE}");
            std::process::ExitCode::FAILURE
        }
    }
}

struct Options {
    quorum: String,
    threshold: usize,
    members: Vec<String>,
    signers: Vec<String>,
    subject_kind: String,
    subject_id: String,
    reason: String,
    detected_at: Option<String>,
    window_start: String,
    window_end: Option<String>,
    declared_at: String,
    out_dir: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        quorum: String::new(),
        threshold: 0,
        members: Vec::new(),
        signers: Vec::new(),
        subject_kind: String::new(),
        subject_id: String::new(),
        reason: String::new(),
        detected_at: None,
        window_start: String::new(),
        window_end: None,
        declared_at: String::new(),
        out_dir: None,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let mut value = |flag: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match arg {
            "--quorum" => o.quorum = value("--quorum")?,
            "--threshold" => {
                o.threshold = value("--threshold")?
                    .parse()
                    .map_err(|_| "bad --threshold".to_string())?
            }
            "--member" => o.members.push(value("--member")?),
            "--signer" => o.signers.push(value("--signer")?),
            "--subject-kind" => o.subject_kind = value("--subject-kind")?,
            "--subject-id" => o.subject_id = value("--subject-id")?,
            "--reason" => o.reason = value("--reason")?,
            "--detected-at" => o.detected_at = Some(value("--detected-at")?),
            "--window-start" => o.window_start = value("--window-start")?,
            "--window-end" => o.window_end = Some(value("--window-end")?),
            "--declared-at" => o.declared_at = value("--declared-at")?,
            "--out-dir" => o.out_dir = Some(PathBuf::from(value("--out-dir")?)),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }
    Ok(o)
}

fn ts(s: &str) -> Result<Timestamp, String> {
    ServiceTimestamp::parse(s)
        .map(|t| t.to_model())
        .map_err(|e| format!("`{s}`: {e}"))
}

fn run(args: &[String]) -> Result<String, String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let options = parse(&args[1..]).map_err(|e| if e.is_empty() { String::new() } else { e })?;
    match command {
        "declare" => declare(&options),
        "" => Err(String::new()),
        other => Err(format!("unknown command `{other}`")),
    }
}

fn declare(o: &Options) -> Result<String, String> {
    if o.quorum.is_empty() {
        return Err("declare needs --quorum".into());
    }
    if o.threshold == 0 {
        return Err("declare needs --threshold".into());
    }
    if o.members.len() < 2 {
        return Err("declare needs at least two --member ids".into());
    }
    if o.signers.is_empty() {
        return Err("declare needs the qualifying set as --signer ids".into());
    }
    if o.signers.len() > o.threshold {
        return Err(format!(
            "a qualifying set is exactly {} signer(s) ({} given): fewer cannot sign, more are redundant",
            o.threshold,
            o.signers.len()
        ));
    }
    let out_dir = o
        .out_dir
        .clone()
        .ok_or_else(|| "declare needs --out-dir".to_string())?;

    // The revocation, parsed exactly as the service's wire layer would
    // (reusing its parsers keeps the binary and the API honest about
    // the same shapes).
    let subject = match o.subject_kind.as_str() {
        "key" => revoked_subject_from_value(&json!({
            "kind": "key", "id": o.subject_id,
        })),
        "node" => revoked_subject_from_value(&json!({
            "kind": "node", "id": o.subject_id,
        })),
        "passport" => revoked_subject_from_value(&json!({
            "kind": "passport", "id": o.subject_id,
        })),
        other => return Err(format!("unknown --subject-kind `{other}`")),
    }
    .map_err(|e| format!("--subject-id: {e}"))?;
    let mut reason_v = json!({"token": o.reason});
    if let Some(d) = &o.detected_at {
        reason_v["detected_at"] = json!(d);
    }
    let reason: RevocationReason =
        reason_from_value(&reason_v).map_err(|e| format!("--reason: {e}"))?;
    if !reason.is_retroactive() {
        return Err(format!(
            "reason `{}` is prospective — it needs no quorum; declare it directly through POST /revocations",
            reason.token()
        ));
    }
    let declared_at = ts(&o.declared_at).map_err(|e| format!("--declared-at: {e}"))?;
    let window = {
        let mut v = json!({"start": o.window_start});
        if let Some(end) = &o.window_end {
            v["end"] = json!(end);
        }
        interval_from_value(&v).map_err(|e| format!("--window-*: {e}"))?
    };

    let quorum =
        unidpp_signatif::graph::NodeId::new(&o.quorum).map_err(|e| format!("--quorum: {e}"))?;
    // The declaring body IS the quorum (a quorate act of the group).
    let declared_by = quorum.clone();
    let revocation = Revocation {
        subject,
        reason,
        declared_at,
        window,
        declared_by: declared_by.clone(),
        quorum: None,
    };

    // The quorum spec and the ceremony.
    let members: Vec<unidpp_signatif::graph::NodeId> = o
        .members
        .iter()
        .map(|m| unidpp_signatif::graph::NodeId::new(m).map_err(|e| format!("--member {m}: {e}")))
        .collect::<Result<_, _>>()?;
    let spec = QuorumSpec {
        quorum_id: quorum.clone(),
        threshold: o.threshold,
        members,
    };
    spec.validate().map_err(|e| e.to_string())?;

    let statement_bytes = revocation.statement_bytes();
    let payload = QuorumAttestation::canonical_bytes(&statement_bytes, &quorum, o.threshold);
    let mut ceremony = RealCeremony::new(None);
    let session = ceremony
        .create_session(SessionInit {
            kind: CeremonyKind::Sign,
            statement: CeremonyStatement {
                label: format!("retroactive-distrust:{}", revocation.subject.label()),
                payload: payload.clone(),
            },
            quorum: spec.clone(),
            expires_at: None,
        })
        .map_err(|e| format!("ceremony session: {e}"))?;

    let signers: Vec<unidpp_signatif::graph::NodeId> = o
        .signers
        .iter()
        .map(|s| unidpp_signatif::graph::NodeId::new(s).map_err(|e| format!("--signer {s}: {e}")))
        .collect::<Result<_, _>>()?;
    for s in &signers {
        if !spec.members.contains(s) {
            return Err(format!("signer {s} is not a member of the quorum"));
        }
    }

    // Round 1: commitments from the qualifying set. Fewer than the
    // threshold leave the session in Pending — share_for then refuses
    // (WrongRound) — and aggregation refuses with ThresholdNotMet.
    for signer in &signers {
        let commitment = ceremony
            .commitment_for(&session, signer)
            .map_err(|e| format!("round 1 ({signer}): {e}"))?;
        ceremony
            .submit_commitment(&session, commitment)
            .map_err(|e| format!("round 1 ({signer}): {e}"))?;
    }
    // Round 2: partials (requires round 1 closed at the threshold).
    for signer in &signers {
        let share = ceremony
            .share_for(&session, signer)
            .map_err(|e| format!("round 2 ({signer}): {e}"))?;
        ceremony
            .submit_share(&session, share)
            .map_err(|e| format!("round 2 ({signer}): {e}"))?;
    }
    let aggregated = ceremony.aggregate(&session).map_err(|e| match e {
        CeremonyError::ThresholdNotMet { have, need } => format!(
            "quorum not met: have {have} of {need} — the ceremony cannot produce a \
             group signature below the threshold (this is the refusal, not a retry hint)"
        ),
        other => format!("aggregation: {other}"),
    })?;
    // The ceremony's own verification: standard Ed25519 under the
    // group key over the Quorum-domain-framed canonical bytes.
    aggregated
        .verify(&CeremonyStatement {
            label: String::new(),
            payload: payload.clone(),
        })
        .map_err(|e| format!("group signature self-check: {e}"))?;

    let attestation = QuorumAttestation {
        quorum: quorum.clone(),
        threshold: o.threshold,
        signatures: vec![aggregated.to_slot()],
    };
    let mut revocation = revocation;
    revocation.quorum = Some(attestation);

    // The quorum node pinning the group key (kind + the registered
    // group key) — built through the same node shape the service
    // round-trips.
    let group_key: GroupKey = ceremony
        .group(&session)
        .map_err(|e| format!("group: {e}"))?;
    let group_public = PublicKey::from_bytes(
        &hex_decode(&group_key.group_public).map_err(|e| format!("group key: {e}"))?,
    )
    .map_err(|e| format!("group key: {e}"))?;
    let mut node = DelegationNode::new(
        quorum.clone(),
        NodeKind::ThresholdGroup {
            threshold: o.threshold,
            members: BTreeSet::from_iter(spec.members.iter().cloned()),
        },
    );
    node.register(RegisteredKey {
        key_id: KeyId::of(&group_public),
        public: group_public,
    });
    let node_v = node_to_value(&node);
    let revocation_v = revocation_to_value(&revocation);
    let ceremony_v = json!({
        "algorithm": group_key.algorithm,
        "threshold": group_key.threshold,
        "members": group_key.members,
        "group_public": group_key.group_public,
        "feldman_commitments": group_key.commitments,
        "signers": signers.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "statement": {
            "subject": revoked_subject_to_value(&revocation.subject),
            "reason": reason_to_value(&revocation.reason),
            "window": interval_to_value(&revocation.window),
            "declared_by": revocation.declared_by.to_string(),
            "sha256": {
                "statement_bytes": unidpp_model::sha256(&[&statement_bytes]).hex(),
                "canonical_payload": unidpp_model::sha256(&[&payload]).hex(),
            },
        },
        "seed_note": "RealCeremony derives the ceremony seed from the public quorum spec — \
                      reproducible for rehearsals and demos, not a production root ceremony \
                      (see signatif's confium::real module docs)",
    });

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;
    let write = |name: &str, v: &serde_json::Value| -> Result<(), String> {
        let path = out_dir.join(name);
        std::fs::write(&path, serde_json::to_string_pretty(v).unwrap())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    };
    write("quorum-node.json", &node_v)?;
    write("revocation.json", &revocation_v)?;
    write("ceremony.json", &ceremony_v)?;

    Ok(format!(
        "{}-of-{} ceremony complete — qualifying set {:?} (no member key can sign alone; \
         the group key matches no member)\n\
         group public key: {}\n\
         wrote {}/quorum-node.json (POST /nodes — pinning is load-bearing),\n\
         {}/revocation.json (POST /revocations), {}/ceremony.json",
        group_key.threshold,
        group_key.members,
        signers.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        hex_encode(group_public.as_bytes()),
        out_dir.display(),
        out_dir.display(),
        out_dir.display(),
    ))
}
