use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use oprf_nullifier::{
    hash_to_curve::{hash_to_field, DEFAULT_TWEAK_BOUND},
    noir_prover::{CurveMode, NoirProver},
    OprfClient, OprfServer,
};

#[derive(Parser)]
#[command(name = "oprf-nullifier-demo")]
struct Cli {
    /// Port to listen on
    #[arg(long, default_value = "3000")]
    port: u16,
}

struct AppState {
    oprf_server: OprfServer,
    noir_prover: NoirProver,
    nullifiers: Mutex<HashSet<String>>,
    client_sessions: Mutex<HashMap<String, ClientSession>>,
}

struct ClientSession {
    blinding_factor: k256::NonZeroScalar,
    input: Vec<u8>,
    witness: oprf_nullifier::hash_to_curve::MapToCurveWitness,
    blinded_point: k256::ProjectivePoint,
}

// ── Request/Response types ──────────────────────────────────

#[derive(Deserialize)]
struct ClientBlindRequest {
    input: String,
}

#[derive(Serialize)]
struct ClientBlindResponse {
    session_id: String,
    side: String,
    steps: Vec<StepData>,
    blinded_point_hex: String,
    proof: ProofData,
    mode: String,
}

#[derive(Serialize, Clone)]
struct ProofData {
    m_hex: String,
    h_hex: String,
    tweak: u32,
    z_hex: String,
    proof_hex: String,
    public_inputs_hex: String,
}

#[derive(Deserialize)]
struct ServerEvalRequest {
    blinded_point_hex: String,
    proof: ServerProofInput,
}

#[derive(Deserialize)]
struct ServerProofInput {
    m_hex: String,
    h_hex: String,
    tweak: u32,
    z_hex: String,
    proof_hex: String,
    public_inputs_hex: String,
}

#[derive(Serialize)]
struct ServerEvalResponse {
    side: String,
    steps: Vec<StepData>,
    evaluated_point_hex: String,
}

#[derive(Deserialize)]
struct ClientFinalizeRequest {
    session_id: String,
    evaluated_point_hex: String,
}

#[derive(Serialize)]
struct ClientFinalizeResponse {
    side: String,
    nullifier: String,
    steps: Vec<StepData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_inputs_hex: Option<String>,
}

#[derive(Deserialize)]
struct RegisterRequest {
    nullifier: String,
    proof_hex: Option<String>,
    public_inputs_hex: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    accepted: bool,
    status: String,
    total_registered: usize,
}

#[derive(Serialize, Clone)]
struct StepData {
    title: String,
    data: serde_json::Value,
}

#[derive(Serialize)]
struct InfoResponse {
    curve: String,
    mode: String,
    acir_opcodes: u32,
    ultrahonk_gates: u32,
}

// ── Server ──────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mode = CurveMode::Secp256k1;

    println!("Mode: {}", mode);
    let state = Arc::new(AppState {
        oprf_server: OprfServer::random(),
        noir_prover: NoirProver::new(mode),
        nullifiers: Mutex::new(HashSet::new()),
        client_sessions: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/info", get(get_info))
        .route("/api/client/blind", post(client_blind))
        .route("/api/server/evaluate", post(server_evaluate))
        .route("/api/client/finalize", post(client_finalize))
        .route("/api/register", post(register_nullifier))
        .route("/api/reset", post(reset_registry))
        .layer(CorsLayer::permissive())
        .with_state(state);

    println!("OPRF Nullifier Demo running at http://localhost:{}", cli.port);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", cli.port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ── INFO: Return current mode ────────────────────────────────

async fn get_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(InfoResponse {
        curve: "secp256k1 (y^2 = x^3 + 7) — full OPRF chain".into(),
        mode: format!("{}", state.noir_prover.mode),
        acir_opcodes: 53213,
        ultrahonk_gates: 197599,
    })
}

// ── CLIENT: Hash + Map-to-Curve + Blind ─────────────────────

async fn client_blind(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ClientBlindRequest>,
) -> impl IntoResponse {
    // Zero-pad input to 32 bytes (circuit expects fixed-size)
    let raw = req.input.as_bytes();
    let mut input_32 = [0u8; 32];
    let len = raw.len().min(32);
    input_32[..len].copy_from_slice(&raw[..len]);

    let mut steps = Vec::new();

    // 1. Hash to field
    let (_m_secp, m_bytes_secp) = hash_to_field(&input_32);
    let m_hex_display = hex::encode(&m_bytes_secp);

    steps.push(StepData {
        title: "SHA-256 -> Field Element".into(),
        data: serde_json::json!({
            "operation": "m = SHA-256(input) mod q_secp256k1",
            "input": req.input,
            "m_hash": format!("0x{}...", &m_hex_display[..24]),
        }),
    });

    // 2. Map to curve with witness
    let blind_req = OprfClient::blind(&input_32);
    let h_affine = blind_req.h.to_affine();
    let h_compressed = hex::encode(h_affine.to_encoded_point(true).as_bytes());

    steps.push(StepData {
        title: "Map to Curve (Witness)".into(),
        data: serde_json::json!({
            "operation": "h = map_to_curve(m) on secp256k1",
            "curve": "secp256k1",
            "tweak_k": blind_req.witness.tweak,
            "circuit_cost": "259 ACIR (increment-and-check)",
        }),
    });

    // 3. Blind
    let blinded_hex = hex::encode(
        blind_req.blinded.to_affine().to_encoded_point(true).as_bytes(),
    );
    steps.push(StepData {
        title: "Blind".into(),
        data: serde_json::json!({
            "operation": "blinded = h * r  (random scalar r)",
            "blinded": format!("0x{}...", &blinded_hex[..24]),
        }),
    });

    // Proof deferred — generated at finalize after receiving server's evaluated point
    steps.push(StepData {
        title: "Proof Deferred".into(),
        data: serde_json::json!({
            "operation": "Full ZK proof will be generated after unblinding (covers entire OPRF chain)",
            "circuit": "53,213 ACIR opcodes / 197,599 UltraHonk gates",
            "proves": [
                "1. SHA-256(input) -> field element",
                "2. Increment-and-check map-to-curve",
                "3. Blinding: blinded = h * r",
                "4. Unblinding: unblinded = evaluated * r^-1",
                "5. Nullifier: SHA-256(input || unblinded)",
            ],
        }),
    });

    let proof = ProofData {
        m_hex: m_hex_display,
        h_hex: h_compressed,
        tweak: blind_req.witness.tweak,
        z_hex: hex::encode(&blind_req.witness.z),
        proof_hex: String::new(),
        public_inputs_hex: String::new(),
    };

    let session_id = hex::encode(&blind_req.witness.z[..8]);
    state.client_sessions.lock().unwrap().insert(
        session_id.clone(),
        ClientSession {
            blinding_factor: blind_req.blinding_factor,
            input: input_32.to_vec(),
            witness: blind_req.witness.clone(),
            blinded_point: blind_req.blinded,
        },
    );

    Json(ClientBlindResponse {
        session_id,
        side: "CLIENT".into(),
        steps,
        blinded_point_hex: blinded_hex,
        proof,
        mode: "secp256k1".into(),
    })
}

// ── SERVER: Evaluate blinded point ───────────────────────────

async fn server_evaluate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ServerEvalRequest>,
) -> impl IntoResponse {
    let mut steps = Vec::new();

    // Proof verification happens at registration (proof covers the entire OPRF chain)
    steps.push(StepData {
        title: "Proof Verification".into(),
        data: serde_json::json!({
            "operation": "Deferred — full proof verified at registration step",
            "reason": "Proof covers entire OPRF chain (hash → map → blind → unblind → nullifier)",
        }),
    });

    // Evaluate blinded point
    let blinded_bytes = hex::decode(&req.blinded_point_hex).unwrap();
    let encoded = k256::EncodedPoint::from_bytes(&blinded_bytes).unwrap();
    let affine = k256::AffinePoint::from_encoded_point(&encoded).unwrap();
    let blinded = k256::ProjectivePoint::from(affine);

    let evaluated = state.oprf_server.evaluate(&blinded);
    let eval_hex = hex::encode(
        evaluated.to_affine().to_encoded_point(true).as_bytes(),
    );

    steps.push(StepData {
        title: "Evaluate Blinded Point".into(),
        data: serde_json::json!({
            "operation": "evaluated = blinded^k  (server secret key k)",
            "evaluated": format!("0x{}...", &eval_hex[..24]),
        }),
    });

    Json(ServerEvalResponse {
        side: "SERVER".into(),
        steps,
        evaluated_point_hex: eval_hex,
    })
    .into_response()
}

// ── Helpers for coordinate extraction ────────────────────────

fn get_affine_x_bytes(p: &k256::AffinePoint) -> [u8; 32] {
    use k256::elliptic_curve::point::AffineCoordinates;
    let mut out = [0u8; 32];
    out.copy_from_slice(p.x().as_slice());
    out
}

fn get_affine_y_bytes(p: &k256::AffinePoint) -> [u8; 32] {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let enc = p.to_encoded_point(false);
    let mut out = [0u8; 32];
    out.copy_from_slice(enc.y().unwrap().as_slice());
    out
}

// ── CLIENT: Unblind + Derive Nullifier + Generate Proof ──────

async fn client_finalize(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ClientFinalizeRequest>,
) -> impl IntoResponse {
    let session = {
        let mut sessions = state.client_sessions.lock().unwrap();
        match sessions.remove(&req.session_id) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ClientFinalizeResponse {
                        side: "CLIENT".into(),
                        nullifier: String::new(),
                        steps: vec![StepData {
                            title: "Error".into(),
                            data: serde_json::json!({"error": "Session not found"}),
                        }],
                        proof_hex: None,
                        public_inputs_hex: None,
                    }),
                )
                    .into_response();
            }
        }
    };

    let eval_bytes = hex::decode(&req.evaluated_point_hex).unwrap();
    let encoded = k256::EncodedPoint::from_bytes(&eval_bytes).unwrap();
    let affine = k256::AffinePoint::from_encoded_point(&encoded).unwrap();
    let evaluated = k256::ProjectivePoint::from(affine);

    let mut steps = Vec::new();

    // Unblind
    let r_scalar: k256::Scalar = *session.blinding_factor;
    let r_inv: k256::Scalar = Option::from(r_scalar.invert()).expect("non-zero scalar");
    let unblinded = evaluated * r_inv;

    let unblinded_affine = unblinded.to_affine();
    let unblinded_hex = hex::encode(unblinded_affine.to_encoded_point(true).as_bytes());

    let unblinded_x = get_affine_x_bytes(&unblinded_affine);
    let unblinded_y = get_affine_y_bytes(&unblinded_affine);

    // Nullifier = SHA-256(input || x || y) — must match circuit
    let input_32: [u8; 32] = session.input.as_slice().try_into()
        .expect("session input must be 32 bytes");

    let nullifier = {
        use k256::sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&input_32);
        hasher.update(&unblinded_x);
        hasher.update(&unblinded_y);
        let null_hash = hasher.finalize();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(null_hash.as_ref());
        buf
    };
    let nullifier_hex = hex::encode(&nullifier);

    steps.push(StepData {
        title: "Unblind".into(),
        data: serde_json::json!({
            "operation": "result = evaluated * r^-1 = H(input)^k",
            "unblinded": format!("0x{}...", &unblinded_hex[..24]),
        }),
    });

    steps.push(StepData {
        title: "Derive Nullifier".into(),
        data: serde_json::json!({
            "operation": "nullifier = SHA-256(input || unblinded_x || unblinded_y)",
            "nullifier": format!("0x{}", &nullifier_hex),
            "property": "Deterministic: same input + same server key = same nullifier",
        }),
    });

    // Prepare proof inputs
    let blinded_affine = session.blinded_point.to_affine();
    let blinded_x = get_affine_x_bytes(&blinded_affine);
    let blinded_y = get_affine_y_bytes(&blinded_affine);
    let evaluated_x = get_affine_x_bytes(&affine);
    let evaluated_y = get_affine_y_bytes(&affine);

    // r as big-endian 32 bytes
    let r_bytes: [u8; 32] = {
        use k256::elliptic_curve::ScalarPrimitive;
        let r_prim: ScalarPrimitive<k256::Secp256k1> = session.blinding_factor.into();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&r_prim.to_bytes());
        buf
    };

    let witness_k = session.witness.tweak;
    let witness_z = session.witness.z;

    // Generate full ZK proof (~198K gates)
    let proof_start = Instant::now();

    let proof_result = {
        let state_clone = state.clone();
        tokio::task::spawn_blocking(move || {
            state_clone.noir_prover.prove(
                &input_32, &r_bytes, witness_k, &witness_z,
                &unblinded_x, &unblinded_y,
                &blinded_x, &blinded_y,
                &evaluated_x, &evaluated_y,
                &nullifier,
            )
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))
        .and_then(|r| r)
    };

    let proof_gen_ms = proof_start.elapsed().as_millis();

    let (proof_hex_val, pi_hex_val, proof_ok) = match &proof_result {
        Ok(pr) => (hex::encode(&pr.proof), hex::encode(&pr.public_inputs), true),
        Err(e) => {
            eprintln!("Proof generation failed: {}", e);
            (String::new(), String::new(), false)
        }
    };

    steps.push(StepData {
        title: "Generate Full ZK Proof".into(),
        data: serde_json::json!({
            "circuit": "Noir / secp256k1 (non-native) / Full OPRF Nullifier",
            "proof_system": "Barretenberg / UltraHonk",
            "proof_generated": proof_ok,
            "proof_size_bytes": proof_hex_val.len() / 2,
            "acir_opcodes": 53213,
            "ultrahonk_gates": 197599,
            "relations": [
                "1. m = SHA-256(input)                 (hash to field)",
                "2. h_x = m * T + k, h_y = z^2        (map-to-curve witness)",
                "3. h_y^2 = h_x^3 + 7                 (on secp256k1)",
                "4. blinded = h * r                    (blinding check)",
                "5. evaluated = unblinded * r           (unblinding check)",
                "6. nullifier = SHA-256(input || unblinded)  (nullifier derivation)",
            ],
            "proof_gen_time": format!("{}ms", proof_gen_ms),
            "map_to_curve_method": "Increment-and-check (259 ACIR vs SSWU+XMD's 3,929 ACIR = 15x savings)",
        }),
    });

    Json(ClientFinalizeResponse {
        side: "CLIENT".into(),
        nullifier: nullifier_hex,
        steps,
        proof_hex: Some(proof_hex_val),
        public_inputs_hex: Some(pi_hex_val),
    })
    .into_response()
}

// ── REGISTRY ────────────────────────────────────────────────

async fn register_nullifier(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Verify the full proof before accepting
    let proof_bytes = req.proof_hex.as_deref()
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_default();
    let pi_bytes = req.public_inputs_hex.as_deref()
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_default();

    if proof_bytes.is_empty() {
        return Json(RegisterResponse {
            accepted: false,
            status: "REJECTED -- no proof provided".into(),
            total_registered: state.nullifiers.lock().unwrap().len(),
        });
    }

    let verify_result = {
        let state_clone = state.clone();
        tokio::task::spawn_blocking(move || {
            state_clone.noir_prover.verify(&proof_bytes, &pi_bytes)
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))
        .and_then(|r| r)
    };

    match verify_result {
        Ok(true) => eprintln!("Full proof verified successfully"),
        Ok(false) => {
            return Json(RegisterResponse {
                accepted: false,
                status: "REJECTED -- proof verification failed".into(),
                total_registered: state.nullifiers.lock().unwrap().len(),
            });
        }
        Err(e) => {
            eprintln!("Proof verification error: {}", e);
            return Json(RegisterResponse {
                accepted: false,
                status: format!("REJECTED -- verification error: {}", e),
                total_registered: state.nullifiers.lock().unwrap().len(),
            });
        }
    }

    let mut registry = state.nullifiers.lock().unwrap();
    let is_new = registry.insert(req.nullifier.clone());
    let count = registry.len();

    Json(RegisterResponse {
        accepted: is_new,
        status: if is_new {
            "ACCEPTED -- new registration".into()
        } else {
            "REJECTED -- duplicate nullifier (sybil detected)".into()
        },
        total_registered: count,
    })
}

async fn reset_registry(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.nullifiers.lock().unwrap().clear();
    state.client_sessions.lock().unwrap().clear();
    (StatusCode::OK, "Registry cleared")
}

async fn serve_index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}
