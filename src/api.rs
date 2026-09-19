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
//! The endpoint table is the served contract itself: every handler
//! carries its `#[utoipa::path]` declaration, the document is served
//! at `/openapi.yaml` (and `/openapi.json`), browsable at `/docs`,
//! and committed as the golden `openapi.yaml`. The public surface
//! (discovery, health, keyring, graph, anchor bundle, trust lists,
//! master list, revocations, operators, evidence) carries the tag
//! `trust`; the operator surface (node, edge, trust-list, master-list
//! and revocation mutations, evidence registration, the audit log)
//! carries the tag `admin` and requires the Bearer token where one is
//! configured.

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
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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
    /// The environment variables this service consumes. This is the
    /// deployment contract: the contract document carries exactly
    /// these names as `x-unidpp-env-keys`, and `from_env` reads the
    /// environment only through this constant. The two signing seeds
    /// are consumed by the service keyring (`Keyring::from_env`),
    /// and `UNIDPP_TRUST_DEV_SEED` selects the keyring's deterministic
    /// seeded-dev mode.
    pub const ENV_KEYS: &'static [&'static str] = &[
        "UNIDPP_TRUST_BIND",
        "UNIDPP_TRUST_ADMIN_TOKEN",
        "UNIDPP_TRUST_STATE_FILE",
        "UNIDPP_TRUST_NO_SEED_FIXTURES",
        "UNIDPP_TRUST_DEV_SEED",
        "UNIDPP_TRUST_SIGN_SEED",
        "UNIDPP_TRUST_SIGN_SEED_P256",
    ];

    /// Resolve the configuration from environment variables.
    pub fn from_env() -> Config {
        let mut c = Config::default();
        let mut vars: HashMap<&str, String> = HashMap::new();
        for key in Self::ENV_KEYS {
            if let Ok(value) = std::env::var(key) {
                vars.insert(*key, value);
            }
        }
        if let Some(bind) = vars.get("UNIDPP_TRUST_BIND") {
            match bind.parse() {
                Ok(addr) => c.bind = addr,
                Err(_) => eprintln!("unidpp-trust: ignoring bad UNIDPP_TRUST_BIND `{bind}`"),
            }
        }
        if let Some(token) = vars.get("UNIDPP_TRUST_ADMIN_TOKEN") {
            if !token.is_empty() {
                c.admin_token = Some(token.clone());
            }
        }
        if let Some(path) = vars.get("UNIDPP_TRUST_STATE_FILE") {
            if !path.is_empty() {
                c.state_file = Some(PathBuf::from(path));
            }
        }
        if let Some(v) = vars.get("UNIDPP_TRUST_NO_SEED_FIXTURES") {
            if v == "1" || v.eq_ignore_ascii_case("true") {
                c.seed_fixtures = false;
            }
        }
        if let Some(seed) = vars.get("UNIDPP_TRUST_DEV_SEED") {
            if !seed.is_empty() {
                c.dev_seed = Some(seed.clone());
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

/// Serve the discovery document.
#[utoipa::path(
    get,
    path = "/",
    tag = "trust",
    responses(
        (status = 200, description = "The discovery document: the service identity, the signing posture (the tree-head domain, both suites, the signature headers), the endpoint table, the revocation semantics, the as-of conventions, the seed-fixture provenance and the authentication rule", body = Value, content_type = "application/json"),
    )
)]
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
            "operators": "GET /operators/{node}?at= — the operator surface: identity (kind, keys), delegation position (edges with scopes), trust-list memberships with validity windows (not_before/superseded_at), master-list attestations, revocation standing",
            "evidence_catalogue": "GET /evidence — metadata only (ids, content types, required scopes, sizes); content never listed",
            "evidence_release": "GET /evidence/{id}?scope= (or X-UniDPP-Scope; requester via ?requester= / X-UniDPP-Requester) — released bytes signed over; an unsatisfying scope is a stated 403 naming the required scope; every release journaled",
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

/// Liveness probe.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "trust",
    responses(
        (status = 200, description = "The service is serving; the signed status names the service and carries the as-of instant", body = Value, content_type = "application/json"),
    )
)]
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

/// Serve the public keyring.
#[utoipa::path(
    get,
    path = "/keyring",
    tag = "trust",
    responses(
        (status = 200, description = "The public keyring: the keyring mode, the per-role suites, key ids and hex-encoded public anchors a verifier pins (the CLI `--anchor`), the signing domain and the verification recipe matching the response headers", body = Value, content_type = "application/json"),
    )
)]
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

/// Serve the full trust graph.
#[utoipa::path(
    get,
    path = "/graph",
    tag = "trust",
    params(
        ("at" = Option<String>, Query, description = "An RFC 3339 instant; the graph is rendered as of that instant (alias `asof`)"),
    ),
    responses(
        (status = 200, description = "The trust graph: the node count, the edge count, the nodes and the delegation edges, stamped with the as-of instant; a verifier reconstructs the signatif objects from this document", body = Value, content_type = "application/json"),
        (status = 400, description = "The `at` parameter is present and is not a valid RFC 3339 instant"),
    )
)]
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

/// Serve the verifier artifact for one jurisdiction.
#[utoipa::path(
    get,
    path = "/anchor-bundle",
    tag = "trust",
    params(
        ("jurisdiction" = String, Query, description = "The jurisdiction whose trust list the bundle carries beside the master list"),
        ("at" = Option<String>, Query, description = "An RFC 3339 instant; the bundle is rendered as of that instant (alias `asof`)"),
    ),
    responses(
        (status = 200, description = "The verifier-shaped anchor bundle: the jurisdiction's trust list and the M-of-K master list, with wire-form keys a verifier rebuilds without touching the asymmetric PublicKey serde", body = Value, content_type = "application/json"),
        (status = 400, description = "The `jurisdiction` parameter is absent, or the `at` parameter is present and is not a valid RFC 3339 instant"),
        (status = 404, description = "No trust list exists for the requested jurisdiction"),
    )
)]
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

/// Serve the jurisdiction trust lists.
#[utoipa::path(
    get,
    path = "/trust-lists",
    tag = "trust",
    params(
        ("at" = Option<String>, Query, description = "An RFC 3339 instant; every entry carries `in_force_at_as_of` for that instant (alias `asof`)"),
        ("jurisdiction" = Option<String>, Query, description = "Restrict the response to one jurisdiction"),
        ("framework" = Option<String>, Query, description = "Restrict the response to the lists whose framework matches this value"),
    ),
    responses(
        (status = 200, description = "The trust lists, each with its jurisdiction, framework and entries with their validity windows, sorted by jurisdiction", body = Value, content_type = "application/json"),
        (status = 400, description = "The `at` parameter is present and is not a valid RFC 3339 instant"),
    )
)]
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

/// Serve one jurisdiction's trust list.
#[utoipa::path(
    get,
    path = "/trust-lists/{jur}",
    tag = "trust",
    params(
        ("jur" = String, Path, description = "The jurisdiction (matched case-insensitively)"),
        ("at" = Option<String>, Query, description = "An RFC 3339 instant; every entry carries `in_force_at_as_of` for that instant (alias `asof`)"),
    ),
    responses(
        (status = 200, description = "The jurisdiction's trust list: jurisdiction, framework and the entries with their validity windows", body = Value, content_type = "application/json"),
        (status = 400, description = "The `at` parameter is present and is not a valid RFC 3339 instant"),
        (status = 404, description = "No trust list exists for the requested jurisdiction"),
    )
)]
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

/// Serve the M-of-K master list.
#[utoipa::path(
    get,
    path = "/master-list",
    tag = "trust",
    params(
        ("at" = Option<String>, Query, description = "An RFC 3339 instant; attestations are verified against the witness set as of that instant (alias `asof`)"),
    ),
    responses(
        (status = 200, description = "The master list: the M-of-K shape, the witness list, and every entry with its attestations, the live per-attestation verification results, the verified-witness count and the quorum verdict", body = Value, content_type = "application/json"),
        (status = 400, description = "The `at` parameter is present and is not a valid RFC 3339 instant"),
    )
)]
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

/// Serve the revocation ledger with the live retroactivity reading.
#[utoipa::path(
    get,
    path = "/revocations",
    tag = "trust",
    params(
        ("at" = Option<String>, Query, description = "An RFC 3339 instant; each declaration is read for void-ab-initio standing at that instant (alias `asof`)"),
        ("known_by" = Option<String>, Query, description = "An RFC 3339 evidentiary cutoff; declarations made after it keep prior as-of verifications valid"),
        ("window" = Option<String>, Query, description = "A distrust window `START..END` (or `START,END`); declarations whose window overlaps it are returned"),
        ("subject" = Option<String>, Query, description = "Restrict the response to declarations naming this subject (prefix match)"),
        ("retroactive" = Option<String>, Query, description = "`true` restricts to retroactive reasons, `false` to prospective reasons"),
    ),
    responses(
        (status = 200, description = "The declarations with the live reading: `known_at_cutoff`, `voids_at_as_of`, `standing_at_as_of`, the quorum verdict for retroactive declarations and the governing rule", body = Value, content_type = "application/json"),
        (status = 400, description = "The `at`, `known_by` or `window` parameter does not parse, or `retroactive` is not a boolean"),
    )
)]
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

/// GET /operators/{node}?at= — the operator surface (TODO.impl 224):
/// one operator's credential directory rendered from the same
/// registries (MobileQR's firm page + credential 有效期 counterpart):
/// identity (kind, registered keys), delegation position (edges in
/// and out with their scopes), trust-list memberships **with their
/// validity windows** (`not_before` / `superseded_at`), master-list
/// attestations, and revocation standing. An unknown operator is a
/// stated 404.
/// Serve the operator surface for one node.
#[utoipa::path(
    get,
    path = "/operators/{node}",
    tag = "trust",
    params(
        ("node" = String, Path, description = "The operator's node id"),
        ("at" = Option<String>, Query, description = "An RFC 3339 instant; memberships are read for force at that instant (alias `asof`)"),
    ),
    responses(
        (status = 200, description = "The operator's credential directory: identity (kind, registered keys), delegation position (edges in and out with their scopes), trust-list memberships with their validity windows, master-list attestations and revocation standing", body = Value, content_type = "application/json"),
        (status = 400, description = "The node id is not a valid operator node id, or the `at` parameter is present and is not a valid RFC 3339 instant"),
        (status = 404, description = "No operator with this node id is known here"),
    )
)]
async fn operator_view(
    State(app): State<Arc<AppState>>,
    Path(node): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let at = match parse_at(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&app, &e),
    };
    let as_of = at.unwrap_or_else(Timestamp::now);
    let Ok(node_id) = unidpp_signatif::graph::NodeId::new(&node) else {
        return bad_request(&app, &format!("`{node}` is not a valid operator node id"));
    };
    let doc = {
        let store = app.store.lock().expect("store poisoned");
        let Some(dn) = store.graph.node(&node_id) else {
            return not_found(&app, &format!("no operator `{node}`"));
        };
        let keys: Vec<Value> = dn
            .keys
            .iter()
            .map(|k| {
                json!({
                    "key_id": k.key_id.to_string(),
                    "suite": k.public.suite().to_string(),
                })
            })
            .collect();
        // Delegation position: edges in and out, scopes carried.
        let mut edges_in: Vec<Value> = Vec::new();
        let mut edges_out: Vec<Value> = Vec::new();
        for e in store.graph.edges() {
            let v = crate::wire::edge_to_value(e);
            if e.child == node_id {
                edges_in.push(v);
            } else if e.parent == node_id {
                edges_out.push(v);
            }
        }
        // Trust-list memberships with validity windows — the
        // operator's credential directory.
        let mut memberships: Vec<Value> = Vec::new();
        for (jur, list) in &store.trust_lists {
            for entry in list.entries.values() {
                if entry.node == node_id {
                    memberships.push(json!({
                        "jurisdiction": jur,
                        "not_before": crate::time::Timestamp::from_model(entry.not_before).to_string(),
                        "superseded_at": entry.superseded_at
                            .map(|t| crate::time::Timestamp::from_model(t).to_string()),
                        "in_force_at_as_of": entry.in_force_at(as_of.to_model()),
                    }));
                }
            }
        }
        memberships.sort_by(|a, b| a["jurisdiction"].as_str().cmp(&b["jurisdiction"].as_str()));
        // Master-list standing: witness attestations over this node.
        let master = store
            .master
            .entries
            .get(&node_id)
            .map(|entry| {
                json!({
                    "attested_by": entry.attestations.len(),
                    "witnesses": entry
                        .attestations
                        .iter()
                        .map(|a| a.witness.to_string())
                        .collect::<Vec<_>>(),
                })
            })
            .unwrap_or(Value::Null);
        // Revocation standing: declarations naming this node.
        let revocations: Vec<Value> = store
            .ledger
            .revocations()
            .iter()
            .filter(|r| matches!(&r.subject, unidpp_signatif::revoke::RevokedSubject::Node(id) if id == &node_id))
            .map(crate::wire::revocation_to_value)
            .collect();
        json!({
            "operator": node_id.to_string(),
            "kind": format!("{:?}", dn.kind),
            "keys": keys,
            "delegated_by": edges_in,
            "delegates": edges_out,
            "trust_list_memberships": memberships,
            "master_list": master,
            "revocations": revocations,
            "as_of": as_of.to_string(),
        })
    };
    signed(&app, StatusCode::OK, &doc, as_of, CachePolicy::Current)
}

/// GET /evidence — the public catalogue: metadata only (ids, content
/// types, required scopes, sizes). Content never appears here; a
/// document is released only under its scope.
/// Serve the gated-evidence catalogue.
#[utoipa::path(
    get,
    path = "/evidence",
    tag = "trust",
    responses(
        (status = 200, description = "The catalogue metadata only: identifiers, content types, descriptions, required scopes and sizes; document content never appears in the catalogue", body = Value, content_type = "application/json"),
    )
)]
async fn evidence_catalogue(State(app): State<Arc<AppState>>) -> Response {
    let doc = {
        let store = app.store.lock().expect("store poisoned");
        store.evidence_list_json()
    };
    signed(
        &app,
        StatusCode::OK,
        &doc,
        Timestamp::now(),
        CachePolicy::Current,
    )
}

/// GET /evidence/{id}?scope=... — release a gated evidence document
/// (TODO.impl 224): the MobileQR `getbase64str` pattern with the
/// honesty doctrine applied. The scope arrives as the `scope` query
/// parameter or the `X-UniDPP-Scope` header (the parameter outranks
/// the header); the requester, when presented, as `requester` or
/// `X-UniDPP-Requester`. A scope that does not satisfy the
/// registration is a **stated 403 naming the required scope** — never
/// a silent 404; a release journals the access decision and the
/// response is signed over the exact bytes returned (integrity is the
/// signature, not a digest field).
/// Release a gated evidence document under its scope.
#[utoipa::path(
    get,
    path = "/evidence/{id}",
    tag = "trust",
    params(
        ("id" = String, Path, description = "The evidence identifier"),
        ("scope" = Option<String>, Query, description = "The requester's scope; the `X-UniDPP-Scope` header is accepted when the parameter is absent, and the parameter outranks the header"),
        ("requester" = Option<String>, Query, description = "The requester identity the journal records; the `X-UniDPP-Requester` header is accepted when the parameter is absent"),
    ),
    responses(
        (status = 200, description = "The document bytes are released and the signature covers the exact bytes returned; the response carries the registered content type and the required scope, and the release is journaled", body = Value, content_type = "application/octet-stream"),
        (status = 403, description = "The presented scope does not satisfy the registration; the refusal is a stated error naming the required scope, and no release is journaled"),
        (status = 404, description = "No evidence document with this identifier is registered"),
    )
)]
async fn evidence_release(
    State(app): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let scope = params
        .get("scope")
        .cloned()
        .or_else(|| header("x-unidpp-scope"))
        .unwrap_or_default();
    let requester = params
        .get("requester")
        .cloned()
        .or_else(|| header("x-unidpp-requester"));
    let released = {
        let mut store = app.store.lock().expect("store poisoned");
        store.release_evidence(&id, requester, &scope)
    };
    match released {
        Ok(evidence) => {
            let body_bytes = evidence.content.clone();
            let mut resp_headers = vec![
                ("content-type".into(), evidence.content_type.clone()),
                ("x-as-of".into(), Timestamp::now().to_string()),
                ("x-unidpp-scope".into(), evidence.required_scope.clone()),
            ];
            resp_headers.extend(sign_headers(&app, &body_bytes));
            let mut builder = Response::builder().status(StatusCode::OK);
            for (k, v) in resp_headers {
                builder = builder.header(k, v);
            }
            builder
                .body(axum::body::Body::from(body_bytes))
                .expect("evidence response parts are valid")
        }
        // The scope refusal is stated with the required scope (403),
        // never a silent 404 — an absent scope is an access denial,
        // not a missing document.
        Err(StoreError::Invalid(msg)) => signed(
            &app,
            StatusCode::FORBIDDEN,
            &json!({ "error": msg }),
            Timestamp::now(),
            CachePolicy::NoStore,
        ),
        Err(StoreError::NotFound(msg)) => not_found(&app, &msg),
        Err(StoreError::Conflict(msg)) => conflict(&app, &msg),
    }
}

/// POST /admin/evidence — register a gated evidence document: id,
/// contentType, description, requiredScope, contentHex (hex-encoded
/// bytes; the journal stores the same encoding, so replay is exact).
/// Register a gated evidence document.
#[utoipa::path(
    post,
    path = "/admin/evidence",
    tag = "admin",
    request_body(content = Value, description = "`{{\"id\": ..., \"requiredScope\": ..., \"contentHex\": ...}}` — the bytes hex-encoded; optional `contentType` (default `application/octet-stream`) and `description`. Ungated registration is refused, and re-registration of an identifier is a conflict because supersession of evidence is a new identifier, not an edit"),
    responses(
        (status = 201, description = "The document is registered; its catalogue metadata and the audit sequence number are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON, a missing `id`, `requiredScope` or `contentHex`, or a `contentHex` that does not decode"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
        (status = 409, description = "An evidence document with this identifier is already registered"),
    )
)]
async fn register_evidence(
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
    let obj = match v.as_object() {
        Some(o) => o,
        None => return bad_request(&app, "body must be a JSON object"),
    };
    let id = match obj.get("id").and_then(Value::as_str) {
        Some(i) if !i.trim().is_empty() => i.to_string(),
        _ => return bad_request(&app, "`id` is required"),
    };
    let required_scope = match obj.get("requiredScope").and_then(Value::as_str) {
        Some(sc) if !sc.trim().is_empty() => sc.to_string(),
        _ => {
            return bad_request(
                &app,
                "`requiredScope` is required — ungated evidence is a public link, not evidence",
            )
        }
    };
    let content = match obj.get("contentHex").and_then(Value::as_str) {
        Some(h) => match crate::hex::hex_decode(h) {
            Ok(b) => b,
            Err(e) => return bad_request(&app, &format!("`contentHex`: {e}")),
        },
        None => return bad_request(&app, "`contentHex` is required"),
    };
    let evidence = crate::store::Evidence {
        id,
        content_type: obj
            .get("contentType")
            .and_then(Value::as_str)
            .unwrap_or("application/octet-stream")
            .to_string(),
        description: obj
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        required_scope,
        content,
    };
    let meta = {
        let mut store = app.store.lock().expect("store poisoned");
        match store.register_evidence(evidence) {
            Ok(rec) => {
                let mut m = store
                    .evidence_meta(&rec_op_id(&rec))
                    .unwrap_or_else(|| json!({}));
                if let Some(o) = m.as_object_mut() {
                    o.insert("audit_seq".into(), json!(rec.seq));
                }
                m
            }
            Err(e) => return store_error(&app, e),
        }
    };
    signed(
        &app,
        StatusCode::CREATED,
        &meta,
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

/// The id of the evidence a RegisterEvidence record carries.
fn rec_op_id(rec: &crate::store::AuditRecord) -> String {
    match &rec.op {
        crate::store::Op::RegisterEvidence { evidence } => evidence.id.clone(),
        _ => String::new(),
    }
}

/// Serve the append-only audit log.
#[utoipa::path(
    get,
    path = "/admin/log",
    tag = "admin",
    params(
        ("limit" = Option<u64>, Query, description = "Records to return (default 100, maximum 10 000)"),
        ("offset" = Option<u64>, Query, description = "Records to skip (default 0)"),
    ),
    responses(
        (status = 200, description = "The audit-log window: the total record count, the offset and the records", body = Value, content_type = "application/json"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
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

/// Register a trust-graph node.
#[utoipa::path(
    post,
    path = "/nodes",
    tag = "admin",
    request_body(content = Value, description = "The node document: `id` and `kind` (root, threshold-group, delegated or end); optional `keys`, which are merged into any existing registration of the same node"),
    responses(
        (status = 201, description = "The node is registered; the stored node and the audit sequence number are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON or an invalid node document"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
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

/// Add a delegation credential to the trust graph.
#[utoipa::path(
    post,
    path = "/edges",
    tag = "admin",
    request_body(content = Value, description = "The parent-signed delegation credential document: `parent`, `child`, the signature slots and the delegated scope"),
    responses(
        (status = 201, description = "The credential is added; the stored credential and the audit sequence number are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON, or a credential the graph rejects (an unknown endpoint, an invalid signature or a scope violation)"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
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

/// Register a jurisdiction trust list.
#[utoipa::path(
    post,
    path = "/trust-lists",
    tag = "admin",
    request_body(content = Value, description = "`{{\"jurisdiction\": ...}}`; optional `framework` and an initial `entries` array, which is applied after the list is registered"),
    responses(
        (status = 201, description = "The list is registered; the jurisdiction, the framework and the audit sequence number are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON, a missing or invalid `jurisdiction`, or an invalid entry in `entries`"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
        (status = 409, description = "A trust list for this jurisdiction is already registered"),
    )
)]
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

/// Upsert one entry of a jurisdiction trust list.
#[utoipa::path(
    post,
    path = "/trust-lists/{jur}/entries",
    tag = "admin",
    params(
        ("jur" = String, Path, description = "The jurisdiction (matched case-insensitively)"),
    ),
    request_body(content = Value, description = "The entry: `node` and `not_before` (RFC 3339); optional `superseded_at`, an RFC 3339 instant whose presence is the withdrawal of the entry"),
    responses(
        (status = 201, description = "The entry is upserted; the jurisdiction, the node, the validity window and the audit sequence number are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON or an invalid entry document"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
        (status = 404, description = "No trust list exists for this jurisdiction"),
    )
)]
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

/// Replace the witness set of the master list.
#[utoipa::path(
    post,
    path = "/master-list/witnesses",
    tag = "admin",
    request_body(content = Value, description = "`{{\"m\": <threshold>, \"witnesses\": [...]}}` — the M-of-K shape is replaced wholesale by the stated threshold and witness keys"),
    responses(
        (status = 201, description = "The witness set is replaced; the new M-of-K shape with the rendered witnesses and the audit sequence number are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON, a missing `m` or `witnesses`, or an `m` that exceeds the witness count"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
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

/// Upsert one master-list entry.
#[utoipa::path(
    post,
    path = "/master-list/entries",
    tag = "admin",
    request_body(content = Value, description = "The entry: `node` and `attestations` (witness, instant, signature slot); every attestation must name a witness that is already registered"),
    responses(
        (status = 201, description = "The entry is upserted; the node, the attestations and the audit sequence number are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON, an invalid entry, or an attestation naming an unregistered witness"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
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

/// Declare a revocation.
#[utoipa::path(
    post,
    path = "/revocations",
    tag = "admin",
    request_body(content = Value, description = "The declaration: `subject`, `reason`, `declared_at` (RFC 3339), `declared_by` and `window`; a retroactive reason additionally requires a quorate attestation (member-key slots, or a threshold-ceremony group signature pinned on the quorum node — see `quorum`)"),
    responses(
        (status = 201, description = "The declaration is recorded; the subject, the reason, the window and the audit sequence number are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON or an invalid declaration document"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
        (status = 422, description = "The declaration is refused on the merits: a retroactive reason without a quorum attestation, or an attestation that does not reach the threshold"),
    )
)]
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
// Interface contract
// ---------------------------------------------------------------------------

/// The routed paths, declared once. The router routes by these
/// constants, the contract document is tested against them, and no
/// route may be declared with a raw literal (the gates enforce both).
pub mod paths {
    pub const ROOT: &str = "/";
    pub const HEALTHZ: &str = "/healthz";
    pub const KEYRING: &str = "/keyring";
    pub const GRAPH: &str = "/graph";
    pub const ANCHOR_BUNDLE: &str = "/anchor-bundle";
    pub const TRUST_LISTS: &str = "/trust-lists";
    pub const TRUST_LIST_ONE: &str = "/trust-lists/{jur}";
    pub const TRUST_LIST_ENTRIES: &str = "/trust-lists/{jur}/entries";
    pub const MASTER_LIST: &str = "/master-list";
    pub const MASTER_LIST_WITNESSES: &str = "/master-list/witnesses";
    pub const MASTER_LIST_ENTRIES: &str = "/master-list/entries";
    pub const REVOCATIONS: &str = "/revocations";
    pub const OPERATOR: &str = "/operators/{node}";
    pub const EVIDENCE: &str = "/evidence";
    pub const EVIDENCE_ONE: &str = "/evidence/{id}";
    pub const ADMIN_LOG: &str = "/admin/log";
    pub const ADMIN_EVIDENCE: &str = "/admin/evidence";
    pub const NODES: &str = "/nodes";
    pub const EDGES: &str = "/edges";
    /// The contract document itself (not an operation of the API).
    pub const CONTRACT_YAML: &str = "/openapi.yaml";
}

/// The OpenAPI model: one declaration per handler (`#[utoipa::path]`),
/// from which the served contract, the golden file and Swagger UI all
/// derive.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "UniDPP trust",
        version = env!("CARGO_PKG_VERSION"),
        description = "UniDPP trust-list service: jurisdiction trust lists per framework, the M-of-K multi-witness master list, and live reason-to-retroactivity revocations. Every response is as-of stamped and co-signed by the service keyring in the tree-head domain (Ed25519 and ECDSA P-256 over the exact body bytes), so a verifier checks the operator's signed statement of state before it trusts the state. Seed fixtures derived from unidpp-signatif's test trust graph make the service useful to a verifier out of the box. Read operations are public; mutations and the audit log require `Authorization: Bearer <UNIDPP_TRUST_ADMIN_TOKEN>` where a token is configured.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(
        discovery, healthz, keyring, graph, anchor_bundle, trust_lists,
        trust_list_one, master_list, revocations, operator_view,
        evidence_catalogue, evidence_release, admin_log, register_evidence,
        register_node, add_edge, register_trust_list, upsert_trust_entry,
        set_witnesses, upsert_master_entry, declare_revocation,
    ),
    tags(
        (name = "trust", description = "The public surface: discovery, health, keyring, graph, anchor bundle, trust lists, master list, revocations, operators, evidence"),
        (name = "admin", description = "The operator surface: node, edge, trust-list, master-list and revocation mutations, evidence registration, the audit log"),
    )
)]
struct ApiDoc;

/// The contract document: the OpenAPI model plus the deployment keys
/// (`x-unidpp-env-keys`). Served at `/openapi.yaml` and committed as
/// the golden `openapi.yaml`.
pub fn contract_yaml() -> String {
    let mut doc = serde_json::to_value(ApiDoc::openapi()).expect("contract serializes");
    doc["info"]["x-unidpp-env-keys"] = json!(Config::ENV_KEYS);
    serde_yaml::to_string(&doc).expect("contract renders as YAML")
}

async fn openapi_yaml() -> Response {
    build_signed(
        StatusCode::OK,
        vec![("content-type".into(), "application/yaml".into())],
        contract_yaml(),
        CachePolicy::Current,
    )
}

// ---------------------------------------------------------------------------
// Router + run
// ---------------------------------------------------------------------------

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
        .route(paths::ROOT, get(discovery))
        .route(paths::HEALTHZ, get(healthz))
        .route(paths::KEYRING, get(keyring))
        .route(paths::GRAPH, get(graph))
        .route(paths::ANCHOR_BUNDLE, get(anchor_bundle))
        .route(
            paths::TRUST_LISTS,
            get(trust_lists).post(register_trust_list),
        )
        .route(paths::TRUST_LIST_ONE, get(trust_list_one))
        .route(paths::TRUST_LIST_ENTRIES, post(upsert_trust_entry))
        .route(paths::MASTER_LIST, get(master_list))
        .route(paths::MASTER_LIST_WITNESSES, post(set_witnesses))
        .route(paths::MASTER_LIST_ENTRIES, post(upsert_master_entry))
        .route(
            paths::REVOCATIONS,
            get(revocations).post(declare_revocation),
        )
        .route(paths::OPERATOR, get(operator_view))
        .route(paths::EVIDENCE, get(evidence_catalogue))
        .route(paths::EVIDENCE_ONE, get(evidence_release))
        .route(paths::ADMIN_LOG, get(admin_log))
        .route(paths::ADMIN_EVIDENCE, post(register_evidence))
        .route(paths::NODES, post(register_node))
        .route(paths::EDGES, post(add_edge))
        .route(paths::CONTRACT_YAML, get(openapi_yaml))
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

// ---------------------------------------------------------------------------
// Contract gates
// ---------------------------------------------------------------------------

#[cfg(test)]
mod contract_gates {
    use super::*;
    use crate::httpc::{request, Url};
    use std::time::Duration;

    /// The contract paths with their documented methods.
    fn documented() -> std::collections::BTreeMap<String, Vec<String>> {
        let doc: Value = serde_yaml::from_str(&contract_yaml()).expect("contract parses");
        doc["paths"]
            .as_object()
            .expect("paths object")
            .iter()
            .map(|(path, item)| {
                let methods = VERBS
                    .iter()
                    .filter(|v| item.get(*v).is_some())
                    .map(|v| v.to_string())
                    .collect();
                (path.clone(), methods)
            })
            .collect()
    }

    const VERBS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

    /// The routed paths, from the constants the router routes by
    /// (the contract route itself carries no operation). This service
    /// routes no tail-wildcard paths, so a constant is also the path's
    /// key in the document.
    fn routed() -> Vec<&'static str> {
        [
            paths::ROOT,
            paths::HEALTHZ,
            paths::KEYRING,
            paths::GRAPH,
            paths::ANCHOR_BUNDLE,
            paths::TRUST_LISTS,
            paths::TRUST_LIST_ONE,
            paths::TRUST_LIST_ENTRIES,
            paths::MASTER_LIST,
            paths::MASTER_LIST_WITNESSES,
            paths::MASTER_LIST_ENTRIES,
            paths::REVOCATIONS,
            paths::OPERATOR,
            paths::EVIDENCE,
            paths::EVIDENCE_ONE,
            paths::ADMIN_LOG,
            paths::ADMIN_EVIDENCE,
            paths::NODES,
            paths::EDGES,
        ]
        .to_vec()
    }

    /// A concrete probe path: every template parameter is replaced
    /// with a value the handlers parse.
    fn probe(path: &str) -> String {
        path.replace("{jur}", "PROBE")
            .replace("{node}", "PROBE")
            .replace("{id}", "PROBE")
    }

    #[test]
    fn the_golden_matches_the_committed_contract() {
        assert_eq!(contract_yaml(), include_str!("../openapi.yaml"));
    }

    #[test]
    #[ignore = "regenerates openapi.yaml after a route change: cargo test -- --ignored export"]
    fn export_golden() {
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"),
            contract_yaml(),
        )
        .expect("golden written");
    }

    #[test]
    fn every_routed_path_is_documented() {
        let doc = documented();
        for path in routed() {
            assert!(doc.contains_key(path), "routed but undocumented: {path}");
        }
    }

    #[test]
    fn every_documented_path_is_routed() {
        let routed: Vec<String> = routed().iter().map(|p| p.to_string()).collect();
        for path in documented().keys() {
            assert!(routed.contains(path), "documented but not routed: {path}");
        }
    }

    #[test]
    fn routes_are_declared_by_constant_not_literal() {
        let src = include_str!("api.rs");
        assert_eq!(
            src.matches(".route(\"").count(),
            0,
            "route paths come from the paths:: constants"
        );
    }

    /// The `VERB /path` endpoint references embedded in the discovery
    /// document must all be contracted operations.
    #[test]
    fn discovery_names_only_contracted_endpoints() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let doc = rt.block_on(async {
            let ts = TestServer::spawn(Config::default())
                .await
                .expect("test server");
            let resp = request(
                "GET",
                &Url::parse(&format!("{}/", ts.base_url)).expect("discovery url"),
                &[],
                None,
                Duration::from_secs(5),
            )
            .await
            .expect("discovery answered");
            ts.stop().await;
            resp.body_string()
        });
        let documented: Vec<String> = documented().into_keys().collect();
        for verb in VERBS.map(str::to_uppercase) {
            let mut rest = doc.as_str();
            while let Some(pos) = rest.find(&verb) {
                let after = &rest[pos + verb.len()..];
                rest = after;
                let Some(path) = after.strip_prefix(" /") else {
                    continue;
                };
                let taken: String = path
                    .chars()
                    .take_while(|c| !matches!(c, ' ' | '"' | '<'))
                    .collect();
                let path = taken.split('?').next().unwrap_or("").to_string();
                if path.is_empty() {
                    continue;
                }
                assert!(
                    documented.contains(&format!("/{path}")),
                    "discovery names `{verb} /{path}` — no such operation in the contract"
                );
            }
        }
    }

    /// The behavioral half: every documented operation answers
    /// anything but 405, and every undocumented method on a documented
    /// path answers 405 — on the live router.
    #[tokio::test]
    async fn the_router_serves_the_contract_exactly() {
        let ts = TestServer::spawn(Config::default())
            .await
            .expect("test server");
        for (path, methods) in documented() {
            let concrete = probe(&path);
            for verb in VERBS {
                let resp = request(
                    &verb.to_uppercase(),
                    &Url::parse(&format!("{}{concrete}", ts.base_url)).expect("probe url"),
                    &[],
                    if verb == "get" {
                        None
                    } else {
                        Some(b"{}".as_slice())
                    },
                    Duration::from_secs(5),
                )
                .await
                .expect("probe answered");
                if methods.contains(&verb.to_string()) {
                    assert_ne!(
                        resp.status, 405,
                        "{verb} {concrete}: the contract says routed, the router says otherwise"
                    );
                } else {
                    assert_eq!(
                        resp.status, 405,
                        "{verb} {concrete}: served but not in the contract"
                    );
                }
            }
        }
        ts.stop().await;
    }
}
