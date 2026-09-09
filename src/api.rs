//! HTTP surface: axum router, handlers, `Config`, `TestServer`. Reads
//! are public (consumers resolve references); mutations and the audit
//! log require a Bearer token when `UNIDPP_TRUST_ADMIN_TOKEN` is set
//! (open in dev mode, mirroring the registry). Every response is
//! as-of stamped (`x-as-of` header + `as_of` JSON field) and signed
//! by the service keyring in the `SigningDomain::TreeHead` domain,
//! which is the SIGNATIF precedent for an operator's signed statement
//! of state — SIGNATIF has no service-response domain; `tree-head` is
//! the closest documented adaptation. The signatures cover the exact
//! response body bytes (deterministic Ed25519 → identical bodies
//! produce identical signatures → safe to cache with a strong `ETag`).
//!
//! Public reads:
//!
//! | Endpoint | Meaning |
//! |---|---|
//! | `GET /` | discovery document |
//! | `GET /healthz` | liveness (signed JSON status) |
//! | `GET /keyring` | public anchors a verifier pins (CLI `--anchor`) |
//! | `GET /trust-lists?at=&jurisdiction=&framework=` | per jurisdiction + framework |
//! | `GET /trust-lists/{jur}?at=` | one jurisdiction's list (entries with `in_force_at_as_of`) |
//! | `GET /master-list` | M-of-K shape with witness list + per-entry live quorum verdicts |
//! | `GET /revocations?at=&known_by=&window=&subject=&retroactive=` | live retroactivity reading |
//! | `GET /graph` | full trust graph (nodes + edges) — verifiers reconstruct and resolve |
//! | `GET /anchor-bundle?jurisdiction=` | the verifier artifact (lists + master) |
//!
//! Admin (Bearer `UNIDPP_TRUST_ADMIN_TOKEN`):
//!
//! | Endpoint | Meaning |
//! |---|---|
//! | `POST /nodes` | upsert a node (merges keys) |
//! | `POST /edges` | add a delegation credential (validated) |
//! | `POST /trust-lists` | register a new trust list |
//! | `POST /trust-lists/{jur}/entries` | upsert a single entry (`superseded_at` = withdrawal) |
//! | `POST /master-list/witnesses` | replace the witness set (m + keys) |
//! | `POST /master-list/entries` | upsert a master-list entry (re-verified live) |
//! | `POST /revocations` | declare (retroactive requires a quorate attestation: member-key slots, or a threshold-ceremony group signature pinned on the quorum node — see `quorum`) |
//! | `GET /admin/log?limit=&offset=` | append-only audit log |

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::keyring::{Keyring, Role};
use crate::seed;
use crate::store::{Store, StoreError};
use crate::time::Timestamp;
use crate::wire::{
    attestations_verified, edge_to_value, interval_to_value, master_entry_quorate,
    master_entry_to_value, reason_to_value, revoked_subject_to_value, slot_to_value,
    witnesses_from_value, witnesses_to_value,
};

/// Cache strategy for a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// Current-state response (default): short cache with
    /// revalidation.
    Current,
    /// Point-in-time response (`?at=...`): the body is fixed for a
    /// given input — `immutable, max-age=86400`.
    PointInTime,
    /// Mutation response: never store.
    NoStore,
}

impl CachePolicy {
    /// The `cache-control` header value for this policy.
    pub fn header_value(self) -> &'static str {
        match self {
            CachePolicy::Current => "public, max-age=30, must-revalidate",
            CachePolicy::PointInTime => "public, max-age=86400, immutable",
            CachePolicy::NoStore => "no-store",
        }
    }
}

/// Deployment configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address (`UNIDPP_TRUST_BIND`).
    pub bind: SocketAddr,
    /// Bearer token guarding mutations and `/admin/*`; `None` = open
    /// (dev mode).
    pub admin_token: Option<String>,
    /// Optional JSONL journal file (append-only audit log, replayed
    /// on start).
    pub state_file: Option<PathBuf>,
    /// Whether to seed the fixture trust graph on first start. Default
    /// true (the fixtures make the service useful to a verifier out
    /// of the box); set `UNIDPP_TRUST_NO_SEED_FIXTURES=1` to skip.
    pub seed_fixtures: bool,
    /// The deterministic dev seed when env-key mode is unavailable.
    pub dev_seed: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8092".parse().unwrap(),
            admin_token: None,
            state_file: None,
            seed_fixtures: true,
            dev_seed: None,
        }
    }
}

impl Config {
    /// Resolve the configuration from environment variables.
    pub fn from_env() -> Config {
        let mut c = Config::default();
        if let Ok(bind) = std::env::var("UNIDPP_TRUST_BIND") {
            match bind.parse() {
                Ok(addr) => c.bind = addr,
                Err(_) => eprintln!("unidpp-trust: ignoring bad UNIDPP_TRUST_BIND `{bind}`"),
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_TRUST_ADMIN_TOKEN") {
            if !token.is_empty() {
                c.admin_token = Some(token);
            }
        }
        if let Ok(path) = std::env::var("UNIDPP_TRUST_STATE_FILE") {
            if !path.is_empty() {
                c.state_file = Some(PathBuf::from(path));
            }
        }
        if let Ok(v) = std::env::var("UNIDPP_TRUST_NO_SEED_FIXTURES") {
            if v == "1" || v.eq_ignore_ascii_case("true") {
                c.seed_fixtures = false;
            }
        }
        if let Ok(seed) = std::env::var("UNIDPP_TRUST_DEV_SEED") {
            if !seed.is_empty() {
                c.dev_seed = Some(seed);
            }
        }
        c
    }
}

/// Shared application state.
pub struct AppState {
    /// Deployment configuration.
    pub config: Config,
    /// The trust store behind a mutex (journal + graph + ledger).
    pub store: Mutex<Store>,
    /// The service keyring signing every response.
    pub keyring: Keyring,
}

impl AppState {
    /// Open the store (journal replay + optional seeding) and hold the
    /// resolved keyring.
    pub fn new(config: Config, keyring: Keyring) -> std::io::Result<AppState> {
        let store = Store::open(config.state_file.as_deref(), config.seed_fixtures)?;
        Ok(AppState {
            config,
            store: Mutex::new(store),
            keyring,
        })
    }
}

// ---------------------------------------------------------------------------
// Signed-response helper (every JSON response is signed)
// ---------------------------------------------------------------------------

/// Sign `body_bytes` with the service keyring and return the base
/// headers (suite headers carry key ids so the verifier picks the
/// right public key from `/keyring`).
fn sign_headers(app: &AppState, body_bytes: &[u8]) -> Vec<(String, String)> {
    use unidpp_signatif::sign::{SignatureSlot, SigningDomain};
    let ed_slot = SignatureSlot::sign(app.keyring.ed25519(), SigningDomain::TreeHead, body_bytes)
        .expect("Ed25519 sign");
    let p_slot = SignatureSlot::sign(app.keyring.p256(), SigningDomain::TreeHead, body_bytes)
        .expect("P-256 sign");
    let ed_sig = ed_slot
        .signature
        .as_deref()
        .map(crate::hex::hex_encode)
        .unwrap_or_default();
    let p_sig = p_slot
        .signature
        .as_deref()
        .map(crate::hex::hex_encode)
        .unwrap_or_default();
    vec![
        ("x-sig-domain".into(), "tree-head".into()),
        ("x-sig-ed25519".into(), ed_sig.clone()),
        (
            "x-sig-key-id-ed25519".into(),
            app.keyring.key_id(Role::SignEd25519).to_string(),
        ),
        ("x-sig-ecdsa-p256".into(), p_sig),
        (
            "x-sig-key-id-ecdsa-p256".into(),
            app.keyring.key_id(Role::SignEcdsaP256).to_string(),
        ),
        // ETag derives from the Ed25519 signature: identical bodies
        // → identical signatures → identical etags → strong caching
        // out of the box. (cache-control is set once, by
        // `build_signed`, from the handler's CachePolicy.)
        ("etag".into(), format!("\"sig-{}\"", &ed_sig[..32])),
    ]
}

fn build_signed(
    status: StatusCode,
    mut headers: Vec<(String, String)>,
    body: String,
    cache: CachePolicy,
) -> Response {
    headers.push(("cache-control".into(), cache.header_value().to_string()));
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

fn signed(
    app: &AppState,
    status: StatusCode,
    doc: &Value,
    as_of: Timestamp,
    cache: CachePolicy,
) -> Response {
    let body = serde_json::to_string_pretty(doc).unwrap();
    let mut headers = vec![
        ("content-type".into(), "application/json".into()),
        ("x-as-of".into(), as_of.to_string()),
    ];
    headers.extend(sign_headers(app, body.as_bytes()));
    build_signed(status, headers, body, cache)
}

fn error_response(app: &AppState, status: StatusCode, msg: &str) -> Response {
    signed(
        app,
        status,
        &json!({ "error": msg }),
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

fn bad_request(app: &AppState, m: &str) -> Response {
    error_response(app, StatusCode::BAD_REQUEST, m)
}
fn conflict(app: &AppState, m: &str) -> Response {
    error_response(app, StatusCode::CONFLICT, m)
}
fn not_found(app: &AppState, m: &str) -> Response {
    error_response(app, StatusCode::NOT_FOUND, m)
}
fn unprocessable(app: &AppState, m: &str) -> Response {
    error_response(app, StatusCode::UNPROCESSABLE_ENTITY, m)
}

fn store_error(app: &AppState, e: StoreError) -> Response {
    match e {
        StoreError::Conflict(m) => conflict(app, &m),
        StoreError::Invalid(m) => bad_request(app, &m),
        StoreError::NotFound(m) => not_found(app, &m),
    }
}

// ---------------------------------------------------------------------------
// Body/query parsing (registry parity)
// ---------------------------------------------------------------------------

fn parse_body(body: &str) -> Result<Value, String> {
    serde_json::from_str(body).map_err(|e| format!("invalid JSON body: {e}"))
}

fn req_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("`{key}` is required"))
}

fn opt_str(v: &Value, key: &str) -> Option<String> {
    match v.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

fn validate_token(s: &str, field: &str) -> Result<(), String> {
    if s.is_empty() || s.contains('/') || s.chars().any(char::is_whitespace) || s.len() > 256 {
        return Err(format!(
            "`{field}` must be 1-256 characters without `/` or whitespace"
        ));
    }
    Ok(())
}

fn parse_at(params: &HashMap<String, String>) -> Result<Option<Timestamp>, String> {
    let raw = params
        .get("at")
        .or_else(|| params.get("asof"))
        .map(String::as_str);
    match raw {
        None | Some("") => Ok(None),
        Some(s) => Timestamp::parse(s)
            .map(Some)
            .map_err(|e| format!("invalid `at` parameter: {e}")),
    }
}

fn opt_query(params: &HashMap<String, String>, key: &str) -> Option<String> {
    params
        .get(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn require_admin(app: &AppState, headers: &HeaderMap) -> Option<Response> {
    let token = app.config.admin_token.as_ref()?;
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if got == Some(token.as_str()) {
        None
    } else {
        Some(error_response(
            app,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        ))
    }
}

// ---------------------------------------------------------------------------
// As-of stamp policy helper
// ---------------------------------------------------------------------------

fn cache_for(at: Option<Timestamp>) -> CachePolicy {
    if at.is_some() {
        CachePolicy::PointInTime
    } else {
        CachePolicy::Current
    }
}

// ---------------------------------------------------------------------------
// Handlers — discovery / health / keyring
// ---------------------------------------------------------------------------

async fn discovery(State(app): State<Arc<AppState>>) -> Response {
    let body = json!({
        "service": "unidpp-trust",
        "version": env!("CARGO_PKG_VERSION"),
        "build_id": option_env!("UNIDPP_BUILD_ID").unwrap_or("dev"),
        "description": "UniDPP trust-list service: jurisdiction trust lists per framework, M-of-K multi-witness master list, live reason-to-retroactivity revocations. All responses signed in the tree-head domain.",
        "signing": {
            "domain": "tree-head",
            "adapter_note": "SIGNATIF has no service-response domain; tree-head (operator's signed statement of state, used for transparency-log signed tree heads) is the closest documented adaptation. Signatures cover the exact body bytes.",
            "suites": ["ed25519", "ecdsa-p256"],
            "headers": {
                "as_of": "x-as-of",
                "domain": "x-sig-domain",
                "ed25519_signature": "x-sig-ed25519",
                "ed25519_key_id": "x-sig-key-id-ed25519",
                "ecdsa_p256_signature": "x-sig-ecdsa-p256",
                "ecdsa_p256_key_id": "x-sig-key-id-ecdsa-p256",
                "etag": "etag",
                "cache_control": "cache-control",
            },
            "keyring_endpoint": "/keyring"
        },
        "endpoints": {
            "discovery": "GET /",
            "health": "GET /healthz",
            "keyring": "GET /keyring",
            "trust_lists": "GET /trust-lists?at=&jurisdiction=&framework=",
            "trust_list_one": "GET /trust-lists/{jur}?at=",
            "master_list": "GET /master-list",
            "revocations": "GET /revocations?at=&known_by=&window=&subject=&retroactive=",
            "graph": "GET /graph",
            "anchor_bundle": "GET /anchor-bundle?jurisdiction=",
            "admin_log": "GET /admin/log?limit=&offset=",
            "register_node": "POST /nodes",
            "add_edge": "POST /edges",
            "register_trust_list": "POST /trust-lists",
            "upsert_trust_entry": "POST /trust-lists/{jur}/entries",
            "set_witnesses": "POST /master-list/witnesses",
            "upsert_master_entry": "POST /master-list/entries",
            "declare_revocation": "POST /revocations",
        },
        "revocation_semantics": {
            "prospective_reasons": ["key-compromise", "cessation", "supersession", "affiliation-change"],
            "retroactive_reasons": ["misissuance", "fraudulent-issuance", "authority-compromised"],
            "rule": "Prospective reasons keep prior as-of verifications valid (timestamping protects, like code signing). Retroactive reasons (misissuance, fraud, authority-compromised) void ab initio within the explicit distrust window [start, end] and re-validate outside it. Both readings are visible per-declaration in the response via `known_at_cutoff` and `voids_at_as_of`."
        },
        "as_of": {
            "query_parameter": "at (alias: asof)",
            "response_header": "x-as-of",
            "point_in_time_cache": "responses to ?at=... carry cache-control: public, max-age=86400, immutable"
        },
        "seed_fixtures": {
            "source": seed::FIXTURE_SOURCE,
            "enabled_by_default": app.config.seed_fixtures,
            "disable_via": "UNIDPP_TRUST_NO_SEED_FIXTURES=1"
        },
        "auth": "mutations and /admin/log require a Bearer token when UNIDPP_TRUST_ADMIN_TOKEN is set"
    });
    signed(
        &app,
        StatusCode::OK,
        &body,
        Timestamp::now(),
        CachePolicy::Current,
    )
}

async fn healthz(State(app): State<Arc<AppState>>) -> Response {
    let body = json!({
        "status": "ok",
        "service": "unidpp-trust",
        "as_of": Timestamp::now().to_string(),
    });
    signed(
        &app,
        StatusCode::OK,
        &body,
        Timestamp::now(),
        CachePolicy::Current,
    )
}

async fn keyring(State(app): State<Arc<AppState>>) -> Response {
    let mut v = app.keyring.to_json();
    if let Some(m) = v.as_object_mut() {
        m.insert("as_of".into(), json!(Timestamp::now().to_string()));
    }
    signed(
        &app,
        StatusCode::OK,
        &v,
        Timestamp::now(),
        CachePolicy::PointInTime,
    )
}

// ---------------------------------------------------------------------------
// Handlers — graph (verifier reconstruction)
// ---------------------------------------------------------------------------

async fn graph(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let at = match parse_at(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let as_of = at.unwrap_or_else(Timestamp::now);
    let body = {
        let store = app.store.lock().expect("store poisoned");
        let nodes: Vec<Value> = store
            .graph
            .nodes()
            .map(crate::wire::node_to_value)
            .collect();
        let edges: Vec<Value> = store.graph.edges().iter().map(edge_to_value).collect();
        json!({
            "as_of": as_of.to_string(),
            "node_count": store.graph.node_count(),
            "edge_count": store.graph.edge_count(),
            "nodes": nodes,
            "edges": edges,
        })
    };
    signed(&app, StatusCode::OK, &body, as_of, cache_for(at))
}

async fn anchor_bundle(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let at = match parse_at(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let as_of = at.unwrap_or_else(Timestamp::now);
    let jur = match opt_query(&params, "jurisdiction") {
        Some(s) => s,
        None => return bad_request(&app, "`jurisdiction` query parameter is required"),
    };
    let jur_key = jur.to_ascii_uppercase();
    let body = {
        let store = app.store.lock().expect("store poisoned");
        let list = match store.trust_lists.get(&jur_key) {
            Some(l) => l.clone(),
            None => return not_found(&app, &format!("no trust list `{jur}`")),
        };
        // Render one verifier-shaped AnchorBundle document. The JSON
        // mirrors signatif's AnchorBundle (trust_lists + master) but
        // resolves types to wire values so verifiers rebuild without
        // touching the asymmetric PublicKey serde.
        let trust_list_json = json!({
            "jurisdiction": list.jurisdiction.clone(),
            "entries": list.entries.values().map(|e| json!({
                "node": e.node.to_string(),
                "not_before": e.not_before.to_string(),
                "superseded_at": e.superseded_at.map(|t| t.to_string()),
            })).collect::<Vec<_>>(),
        });
        let master_json = json!({
            "m": store.master.m,
            "k": store.master.k,
            "witnesses": store.master.witnesses.iter().map(|(id, k)| json!({
                "node": id.to_string(),
                "suite": k.suite().to_string(),
                "public": crate::hex::hex_encode(k.as_bytes()),
                "public_len": k.as_bytes().len(),
            })).collect::<Vec<_>>(),
            "entries": store.master.entries.values().map(master_entry_to_value).collect::<Vec<_>>(),
        });
        json!({
            "as_of": as_of.to_string(),
            "jurisdiction": jur,
            "trust_lists": [trust_list_json],
            "master": master_json,
        })
    };
    signed(&app, StatusCode::OK, &body, as_of, cache_for(at))
}

// ---------------------------------------------------------------------------
// Handlers — trust lists
// ---------------------------------------------------------------------------

async fn trust_lists(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let at = match parse_at(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let as_of = at.unwrap_or_else(Timestamp::now);
    let framework_filter = opt_query(&params, "framework");
    let jur_filter = opt_query(&params, "jurisdiction").map(|s| s.to_ascii_uppercase());
    let body = {
        let store = app.store.lock().expect("store poisoned");
        let mut out: Vec<Value> = Vec::new();
        for (key, list) in &store.trust_lists {
            if let Some(j) = &jur_filter {
                if key != j {
                    continue;
                }
            }
            let framework = store.frameworks.get(key).and_then(|f| f.clone());
            if let Some(f) = &framework_filter {
                if framework.as_deref() != Some(f.as_str()) {
                    continue;
                }
            }
            let entries: Vec<Value> = list
                .entries
                .values()
                .map(|e| {
                    json!({
                        "node": e.node.to_string(),
                        "not_before": e.not_before.to_string(),
                        "superseded_at": e.superseded_at.map(|t| t.to_string()),
                        "in_force_at_as_of": e.in_force_at(as_of.to_model()),
                    })
                })
                .collect();
            out.push(json!({
                "jurisdiction": list.jurisdiction.clone(),
                "framework": framework,
                "entries": entries,
            }));
        }
        out.sort_by(|a, b| {
            a["jurisdiction"]
                .as_str()
                .unwrap_or("")
                .cmp(b["jurisdiction"].as_str().unwrap_or(""))
        });
        json!({
            "as_of": as_of.to_string(),
            "count": out.len(),
            "trust_lists": out,
        })
    };
    signed(&app, StatusCode::OK, &body, as_of, cache_for(at))
}

async fn trust_list_one(
    State(app): State<Arc<AppState>>,
    Path(jur): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let at = match parse_at(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let as_of = at.unwrap_or_else(Timestamp::now);
    let jur_key = jur.to_ascii_uppercase();
    let body = {
        let store = app.store.lock().expect("store poisoned");
        let list = match store.trust_lists.get(&jur_key) {
            Some(l) => l.clone(),
            None => return not_found(&app, &format!("no trust list `{jur}`")),
        };
        let framework = store.frameworks.get(&jur_key).and_then(|f| f.clone());
        let entries: Vec<Value> = list
            .entries
            .values()
            .map(|e| {
                json!({
                    "node": e.node.to_string(),
                    "not_before": e.not_before.to_string(),
                    "superseded_at": e.superseded_at.map(|t| t.to_string()),
                    "in_force_at_as_of": e.in_force_at(as_of.to_model()),
                })
            })
            .collect();
        json!({
            "as_of": as_of.to_string(),
            "jurisdiction": list.jurisdiction.clone(),
            "framework": framework,
            "entries": entries,
        })
    };
    signed(&app, StatusCode::OK, &body, as_of, cache_for(at))
}

// ---------------------------------------------------------------------------
// Handlers — master list (M-of-K)
// ---------------------------------------------------------------------------

async fn master_list(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let at = match parse_at(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let as_of = at.unwrap_or_else(Timestamp::now);
    let body = {
        let store = app.store.lock().expect("store poisoned");
        let witnesses_view = witnesses_to_value(&store.master);
        let entry_views: Vec<Value> = store
            .master
            .entries
            .values()
            .map(|entry| {
                let verified = attestations_verified(entry, &store.master.witnesses);
                let verified_count = verified.iter().filter(|v| **v).count();
                let mut rendered_atts = Vec::with_capacity(entry.attestations.len());
                for (i, att) in entry.attestations.iter().enumerate() {
                    rendered_atts.push(json!({
                        "witness": att.witness.to_string(),
                        "at": att.at.to_string(),
                        "slot": slot_to_value(&att.slot),
                        "verified": verified[i],
                    }));
                }
                json!({
                    "node": entry.node.to_string(),
                    "attestations": rendered_atts,
                    "verified_witnesses": verified_count,
                    "quorate": master_entry_quorate(entry, &store.master.witnesses, store.master.m),
                    "threshold_required": store.master.m,
                })
            })
            .collect();
        json!({
            "as_of": as_of.to_string(),
            "m_of_k": { "m": store.master.m, "k": store.master.k },
            "witnesses": witnesses_view,
            "entries": entry_views,
        })
    };
    signed(&app, StatusCode::OK, &body, as_of, cache_for(at))
}

// ---------------------------------------------------------------------------
// Handlers — revocations (live retroactivity)
// ---------------------------------------------------------------------------

fn parse_window_filter(
    params: &HashMap<String, String>,
) -> Result<Option<(Timestamp, Option<Timestamp>)>, String> {
    let raw = match opt_query(params, "window") {
        Some(s) => s,
        None => return Ok(None),
    };
    let (start, end) = if let Some((a, b)) = raw.split_once("..") {
        (a.trim(), Some(b.trim()))
    } else if let Some((a, b)) = raw.split_once(',') {
        (a.trim(), Some(b.trim()))
    } else {
        return Err(format!(
            "`window` must be `START..END` or `START,END`: `{raw}`"
        ));
    };
    let start_ts = Timestamp::parse(start).map_err(|e| format!("window start: {e}"))?;
    let end_ts = match end {
        Some(s) if !s.is_empty() => {
            Some(Timestamp::parse(s).map_err(|e| format!("window end: {e}"))?)
        }
        _ => None,
    };
    Ok(Some((start_ts, end_ts)))
}

async fn revocations(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let at = match parse_at(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let as_of = at.unwrap_or_else(Timestamp::now);
    let known_by = opt_query(&params, "known_by")
        .map(|s| Timestamp::parse(&s).map_err(|e| format!("`known_by`: {e}")))
        .transpose();
    let known_by = match known_by {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let subject_filter = opt_query(&params, "subject");
    let retroactive_filter = match opt_query(&params, "retroactive") {
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            other => {
                return bad_request(
                    &app,
                    &format!("`retroactive` must be true/false: `{other}`"),
                )
            }
        },
        None => None,
    };
    let window_filter = match parse_window_filter(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let body = {
        let store = app.store.lock().expect("store poisoned");
        let mut out: Vec<Value> = Vec::new();
        let mut seq = 0u64;
        for r in store.ledger.revocations() {
            seq += 1;
            if let Some(retro) = retroactive_filter {
                if r.reason.is_retroactive() != retro {
                    continue;
                }
            }
            if let Some(subj) = &subject_filter {
                if r.subject.label() != subj.as_str() {
                    // Allow a prefix match: "key:k-abc" → matches any
                    // key:k-abc... label. This is cheap and avoids
                    // forking the wire form into two filter shapes.
                    if !r.subject.label().starts_with(subj.as_str()) {
                        continue;
                    }
                }
            }
            if let Some((wstart, wend)) = &window_filter {
                let window_end = r.window.to.unwrap_or(r.window.from);
                let wstart_m = wstart.to_model();
                let contains_start = wstart_m >= r.window.from && wstart_m <= window_end;
                let contains_end = match wend {
                    Some(we) => {
                        let we_m = we.to_model();
                        we_m >= r.window.from && we_m <= window_end
                    }
                    None => r.window.to.is_none(),
                };
                if !(contains_start || contains_end) {
                    continue;
                }
            }
            let known_at_cutoff = match known_by {
                Some(cutoff) => r.declared_at <= cutoff.to_model(),
                None => true,
            };
            let voids_at_as_of = known_at_cutoff && r.voids(as_of.to_model());
            let standing_at_as_of = if !voids_at_as_of {
                "valid"
            } else if r.reason.is_retroactive() {
                "void-ab-initio"
            } else {
                "suspended-from"
            };
            let verifications_at_stand = !voids_at_as_of;
            let v = if r.reason.is_retroactive() {
                r.quorum
                    .as_ref()
                    .map(|q| crate::quorum::verdict(&store.graph, q, &r.statement_bytes()))
            } else {
                None
            };
            let quorate = v.as_ref().map(|v| v.quorate).unwrap_or(false);
            let quorum_view = r.quorum.as_ref().map(|q| {
                json!({
                    "quorum": q.quorum.to_string(),
                    "threshold": q.threshold,
                    "form": v.as_ref().map(|v| v.form.token()),
                    "verified_count": v.as_ref().map(|v| v.member_verified),
                    "group_verified": v.as_ref().map(|v| v.group_verified),
                    "quorate": quorate,
                    "signatures": q.signatures.iter().map(slot_to_value).collect::<Vec<_>>(),
                })
            });
            out.push(json!({
                "seq": seq,
                "subject": revoked_subject_to_value(&r.subject),
                "reason": reason_to_value(&r.reason),
                "declared_at": r.declared_at.to_string(),
                "declared_by": r.declared_by.to_string(),
                "window": interval_to_value(&r.window),
                "quorum": quorum_view,
                "known_at_cutoff": known_at_cutoff,
                "voids_at_as_of": voids_at_as_of,
                "standing_at_as_of": standing_at_as_of,
                "verifications_at_stand": verifications_at_stand,
                "rule": if r.reason.is_retroactive() {
                    "retroactive: artifacts dated inside the window are void ab initio; outside re-validated"
                } else {
                    "prospective: acts dated before the window/open-end stand; from the effect moment onward, suspended"
                }
            }));
        }
        json!({
            "as_of": as_of.to_string(),
            "known_by": known_by.map(|t| t.to_string()),
            "query": {
                "at": at.map(|t| t.to_string()),
                "known_by": known_by.map(|t| t.to_string()),
                "subject": subject_filter,
                "retroactive": retroactive_filter,
                "window": window_filter.map(|(a, b)| json!({"start": a.to_string(), "end": b.map(|t| t.to_string())})),
            },
            "semantics": {
                "prospective_reasons": ["key-compromise", "cessation", "supersession", "affiliation-change"],
                "retroactive_reasons": ["misissuance", "fraudulent-issuance", "authority-compromised"],
                "rule": "Prospective reasons keep prior as-of verifications valid. Retroactive reasons (misissuance/fraud) void ab initio within the explicit window and re-validate outside it."
            },
            "count": out.len(),
            "revocations": out,
        })
    };
    signed(&app, StatusCode::OK, &body, as_of, cache_for(at))
}

// ---------------------------------------------------------------------------
// Admin — mutations
// ---------------------------------------------------------------------------

async fn admin_log(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(10_000);
    let offset = params
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let view = {
        let store = app.store.lock().expect("store poisoned");
        store.log_json(limit, offset)
    };
    signed(
        &app,
        StatusCode::OK,
        &view,
        Timestamp::now(),
        CachePolicy::Current,
    )
}

async fn register_node(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let node = match crate::wire::node_from_value(&v) {
        Ok(n) => n,
        Err(e) => return bad_request(&app, &e),
    };
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        match store.register_node(node.clone()) {
            Ok(r) => r,
            Err(e) => return store_error(&app, e),
        }
    };
    let mut body = crate::wire::node_to_value(&node);
    if let Some(m) = body.as_object_mut() {
        m.insert("audit_seq".into(), json!(rec.seq));
    }
    signed(
        &app,
        StatusCode::CREATED,
        &body,
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

async fn add_edge(State(app): State<Arc<AppState>>, headers: HeaderMap, body: String) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let cred = match crate::wire::edge_from_value(&v) {
        Ok(c) => c,
        Err(e) => return bad_request(&app, &e),
    };
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        match store.add_edge(cred.clone()) {
            Ok(r) => r,
            Err(e) => return store_error(&app, e),
        }
    };
    let mut body = edge_to_value(&cred);
    if let Some(m) = body.as_object_mut() {
        m.insert("audit_seq".into(), json!(rec.seq));
    }
    signed(
        &app,
        StatusCode::CREATED,
        &body,
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

async fn register_trust_list(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let jurisdiction = match req_str(&v, "jurisdiction") {
        Ok(s) => s.trim().to_string(),
        Err(e) => return bad_request(&app, &e),
    };
    if let Err(e) = validate_token(&jurisdiction, "jurisdiction") {
        return bad_request(&app, &e);
    }
    let framework = opt_str(&v, "framework");
    // Optional initial entries — applied after the list is registered.
    let entries_v = v.get("entries").and_then(Value::as_array).cloned();
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        let rec = match store.register_trust_list(jurisdiction.clone(), framework.clone()) {
            Ok(r) => r,
            Err(e) => return store_error(&app, e),
        };
        if let Some(arr) = entries_v {
            for entry_v in arr {
                let entry = match crate::wire::trust_entry_from_value(&entry_v) {
                    Ok(e) => e,
                    Err(e) => return bad_request(&app, &e),
                };
                if let Err(e) = store.upsert_trust_entry(
                    jurisdiction.clone(),
                    entry.node.clone(),
                    entry.not_before,
                    entry.superseded_at,
                ) {
                    return store_error(&app, e);
                }
            }
        }
        rec
    };
    let body = json!({
        "jurisdiction": jurisdiction.to_ascii_uppercase(),
        "framework": framework,
        "audit_seq": rec.seq,
        "as_of": Timestamp::now().to_string(),
    });
    signed(
        &app,
        StatusCode::CREATED,
        &body,
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

async fn upsert_trust_entry(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(jur): Path<String>,
    body: String,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let entry = match crate::wire::trust_entry_from_value(&v) {
        Ok(e) => e,
        Err(e) => return bad_request(&app, &e),
    };
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        match store.upsert_trust_entry(
            jur.clone(),
            entry.node.clone(),
            entry.not_before,
            entry.superseded_at,
        ) {
            Ok(r) => r,
            Err(e) => return store_error(&app, e),
        }
    };
    let body = json!({
        "jurisdiction": jur,
        "node": entry.node.to_string(),
        "not_before": entry.not_before.to_string(),
        "superseded_at": entry.superseded_at.map(|t| t.to_string()),
        "audit_seq": rec.seq,
        "as_of": Timestamp::now().to_string(),
    });
    signed(
        &app,
        StatusCode::CREATED,
        &body,
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

async fn set_witnesses(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let m = match v.get("m").and_then(Value::as_u64) {
        Some(n) => n as usize,
        None => return bad_request(&app, "`m` (number >= 1) is required"),
    };
    let ws_v = match v.get("witnesses").and_then(Value::as_array) {
        Some(a) => a.clone(),
        None => return bad_request(&app, "`witnesses` array is required"),
    };
    let witnesses = match witnesses_from_value(&Value::Array(ws_v)) {
        Ok(w) => w,
        Err(e) => return bad_request(&app, &e),
    };
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        match store.set_witnesses(m, witnesses.clone()) {
            Ok(r) => r,
            Err(e) => return store_error(&app, e),
        }
    };
    let body = json!({
        "m": m,
        "k": witnesses.len(),
        "witnesses": witnesses_to_value(&unidpp_signatif::graph::MasterList::new(m, BTreeMap::from_iter(witnesses))),
        "audit_seq": rec.seq,
        "as_of": Timestamp::now().to_string(),
    });
    signed(
        &app,
        StatusCode::CREATED,
        &body,
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

async fn upsert_master_entry(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let entry = match crate::wire::master_entry_from_value(&v) {
        Ok(e) => e,
        Err(e) => return bad_request(&app, &e),
    };
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        match store.upsert_master_entry(entry.clone()) {
            Ok(r) => r,
            Err(e) => return store_error(&app, e),
        }
    };
    let body = json!({
        "node": entry.node.to_string(),
        "attestations": entry.attestations.iter().map(crate::wire::witness_attestation_to_value).collect::<Vec<_>>(),
        "audit_seq": rec.seq,
        "as_of": Timestamp::now().to_string(),
    });
    signed(
        &app,
        StatusCode::CREATED,
        &body,
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

async fn declare_revocation(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let revocation = match crate::wire::revocation_from_value(&v) {
        Ok(r) => r,
        Err(e) => return bad_request(&app, &e),
    };
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        match store.declare_revocation(revocation.clone()) {
            Ok(r) => r,
            Err(StoreError::Invalid(m)) => return unprocessable(&app, &m),
            Err(StoreError::Conflict(m)) => return conflict(&app, &m),
            Err(StoreError::NotFound(m)) => return not_found(&app, &m),
        }
    };
    let body = json!({
        "subject": revoked_subject_to_value(&revocation.subject),
        "reason": reason_to_value(&revocation.reason),
        "declared_at": revocation.declared_at.to_string(),
        "declared_by": revocation.declared_by.to_string(),
        "window": interval_to_value(&revocation.window),
        "audit_seq": rec.seq,
        "as_of": Timestamp::now().to_string(),
    });
    signed(
        &app,
        StatusCode::CREATED,
        &body,
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

// ---------------------------------------------------------------------------
// Router + run
// ---------------------------------------------------------------------------

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/keyring", get(keyring))
        .route("/graph", get(graph))
        .route("/anchor-bundle", get(anchor_bundle))
        .route("/trust-lists", get(trust_lists))
        .route("/trust-lists/{jur}", get(trust_list_one))
        .route("/master-list", get(master_list))
        .route("/revocations", get(revocations))
        .route("/admin/log", get(admin_log))
        .route("/nodes", post(register_node))
        .route("/edges", post(add_edge))
        .route("/trust-lists", post(register_trust_list))
        .route("/trust-lists/{jur}/entries", post(upsert_trust_entry))
        .route("/master-list/witnesses", post(set_witnesses))
        .route("/master-list/entries", post(upsert_master_entry))
        .route("/revocations", post(declare_revocation))
        .with_state(app)
}

pub async fn run(config: Config) -> std::io::Result<()> {
    let (keyring, warnings) = Keyring::from_env(config.dev_seed.as_deref());
    for w in &warnings {
        eprintln!("unidpp-trust: {w}");
    }
    if keyring.mode() == crate::keyring::KeyringMode::SeededDev {
        eprintln!(
            "unidpp-trust: WARNING running with seeded-dev keyring \
             (mode = seeded-dev; set UNIDPP_TRUST_SIGN_SEED and \
              UNIDPP_TRUST_SIGN_SEED_P256 for production)"
        );
    }
    let app = Arc::new(AppState::new(config, keyring)?);
    let listener = TcpListener::bind(app.config.bind).await?;
    eprintln!("unidpp-trust listening on http://{}", app.config.bind);
    axum::serve(listener, router(app)).await
}

/// A spawned server on an ephemeral port (integration tests and
/// embedders). `stop()` waits for the listener to be released.
pub struct TestServer {
    pub addr: SocketAddr,
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    pub async fn spawn(config: Config) -> std::io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (keyring, _warnings) = Keyring::from_env(config.dev_seed.as_deref());
        let app = Arc::new(AppState::new(config, keyring)?);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let serve = axum::serve(listener, router(app)).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(e) = serve.await {
                eprintln!("unidpp-trust: server task ended: {e}");
            }
        });
        Ok(TestServer {
            addr,
            base_url: format!("http://{addr}"),
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}
