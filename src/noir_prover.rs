//! Noir circuit proof generation and verification.
//!
//! Proves the full OPRF nullifier chain on secp256k1 (non-native over BN254), ~198K gates.

use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CurveMode {
    /// secp256k1 — non-native over BN254, full OPRF chain, ~198K UltraHonk gates
    Secp256k1,
}

impl std::fmt::Display for CurveMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurveMode::Secp256k1 => write!(f, "secp256k1 (non-native, full OPRF chain)"),
        }
    }
}

// ── Witness TOML generation ─────────────────────────────────

/// Generate Prover.toml for the full nullifier circuit.
///
/// The circuit proves: SHA-256 -> map-to-curve -> blind -> unbind -> nullifier
/// all on secp256k1 (non-native over BN254).
pub fn generate_prover_toml(
    input: &[u8; 32],
    r_bytes: &[u8; 32],
    witness_k: u32,
    witness_z_bytes: &[u8; 32],
    unblinded_x: &[u8; 32],
    unblinded_y: &[u8; 32],
    blinded_x: &[u8; 32],
    blinded_y: &[u8; 32],
    evaluated_x: &[u8; 32],
    evaluated_y: &[u8; 32],
    nullifier: &[u8; 32],
) -> String {
    let fmt_bytes = |name: &str, bytes: &[u8; 32]| -> String {
        let items: Vec<String> = bytes.iter().map(|b| format!("{}", b)).collect();
        format!("{} = [{}]\n", name, items.join(", "))
    };

    let mut toml = String::new();
    toml.push_str(&fmt_bytes("input", input));
    toml.push_str(&fmt_bytes("r_bytes", r_bytes));
    toml.push_str(&format!("witness_k = {}\n", witness_k));
    toml.push_str(&fmt_bytes("witness_z_bytes", witness_z_bytes));
    toml.push_str(&fmt_bytes("unblinded_x_bytes", unblinded_x));
    toml.push_str(&fmt_bytes("unblinded_y_bytes", unblinded_y));
    toml.push_str(&fmt_bytes("blinded_x_bytes", blinded_x));
    toml.push_str(&fmt_bytes("blinded_y_bytes", blinded_y));
    toml.push_str(&fmt_bytes("evaluated_x_bytes", evaluated_x));
    toml.push_str(&fmt_bytes("evaluated_y_bytes", evaluated_y));
    toml.push_str(&fmt_bytes("nullifier", nullifier));
    toml
}

/// Compute all witness values for the nullifier circuit
/// using k256 for secp256k1 operations.
pub fn compute_witness(
    input: &[u8; 32],
    server_key: &k256::NonZeroScalar,
) -> (String, Vec<u8>) {
    use k256::{
        elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, ScalarPrimitive},
        sha2::{Digest, Sha256},
        NonZeroScalar, Scalar,
    };
    use crate::hash_to_curve::{hash_to_curve_with_witness, DEFAULT_TWEAK_BOUND};

    // Step 1+2: hash input → map to curve
    let (h_proj, mtc_witness) = hash_to_curve_with_witness(input, DEFAULT_TWEAK_BOUND)
        .expect("hash_to_curve should succeed");

    // Step 3: blinding
    let r = NonZeroScalar::random(&mut rand_core::OsRng);
    let blinded = h_proj * *r;

    // Step 4: server evaluation
    let evaluated = blinded * **server_key;

    // Step 5: unblinding
    let r_scalar: Scalar = *r;
    let r_inv: Scalar = Option::from(r_scalar.invert()).expect("non-zero scalar");
    let unblinded = evaluated * r_inv;

    // Get affine coordinates as big-endian bytes
    let blinded_affine = blinded.to_affine();
    let evaluated_affine = evaluated.to_affine();
    let unblinded_affine = unblinded.to_affine();

    let affine_x_bytes = |p: &k256::AffinePoint| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(p.x().as_slice());
        out
    };
    let affine_y_bytes = |p: &k256::AffinePoint| -> [u8; 32] {
        let enc = p.to_encoded_point(false);
        let mut out = [0u8; 32];
        out.copy_from_slice(enc.y().unwrap().as_slice());
        out
    };

    let blinded_x = affine_x_bytes(&blinded_affine);
    let blinded_y = affine_y_bytes(&blinded_affine);
    let evaluated_x = affine_x_bytes(&evaluated_affine);
    let evaluated_y = affine_y_bytes(&evaluated_affine);
    let unblinded_x = affine_x_bytes(&unblinded_affine);
    let unblinded_y = affine_y_bytes(&unblinded_affine);

    // r as big-endian 32 bytes (scalar field element)
    let r_prim: ScalarPrimitive<k256::Secp256k1> = r.into();
    let r_bytes_arr: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&r_prim.to_bytes());
        buf
    };

    // Step 6: nullifier = SHA-256(input || unblinded_x || unblinded_y)
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.update(&unblinded_x);
    hasher.update(&unblinded_y);
    let null_hash = hasher.finalize();
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(null_hash.as_ref());

    let toml = generate_prover_toml(
        input,
        &r_bytes_arr,
        mtc_witness.tweak,
        &mtc_witness.z,
        &unblinded_x,
        &unblinded_y,
        &blinded_x,
        &blinded_y,
        &evaluated_x,
        &evaluated_y,
        &nullifier,
    );

    (toml, nullifier.to_vec())
}

// ── Prover ──────────────────────────────────────────────────

pub struct NoirProver {
    nargo_bin: PathBuf,
    bb_bin: PathBuf,
    circuit_dir: PathBuf,
    artifact_name: String,
    pub mode: CurveMode,
}

#[derive(Debug)]
pub struct ProofResult {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl NoirProver {
    pub fn new(mode: CurveMode) -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

        let prover = Self {
            nargo_bin: PathBuf::from(format!("{}/.nargo/bin/nargo", home)),
            bb_bin: PathBuf::from(format!("{}/.bb/bb", home)),
            circuit_dir: PathBuf::from("noir-circuit"),
            artifact_name: "oprf_nullifier_full_nonnative".to_string(),
            mode,
        };

        // Pre-generate VK if needed
        let vk_dir = prover.circuit_dir.join("target/vk");
        std::fs::create_dir_all(&vk_dir).ok();
        if !vk_dir.join("vk").exists() {
            eprintln!("Generating verification key for {} ...", mode);
            let json_name = format!("target/{}.json", prover.artifact_name);
            let _ = Command::new(&prover.bb_bin)
                .args(["write_vk", "-b", &json_name, "-o", "target/vk"])
                .current_dir(&prover.circuit_dir)
                .output();
        }

        prover
    }

    fn json_path(&self) -> String {
        format!("target/{}.json", self.artifact_name)
    }

    fn witness_path(&self) -> String {
        format!("target/{}.gz", self.artifact_name)
    }

    /// Run nargo execute + bb prove, return proof bytes.
    fn prove_raw(&self, toml_content: &str) -> Result<ProofResult, String> {
        // 1. Write Prover.toml
        std::fs::write(self.circuit_dir.join("Prover.toml"), toml_content)
            .map_err(|e| format!("Failed to write Prover.toml: {}", e))?;

        // 2. nargo execute
        let exec = Command::new(&self.nargo_bin)
            .arg("execute")
            .current_dir(&self.circuit_dir)
            .output()
            .map_err(|e| format!("nargo execute: {}", e))?;
        if !exec.status.success() {
            return Err(format!("nargo execute failed: {}", String::from_utf8_lossy(&exec.stderr)));
        }

        // 3. bb prove
        let proof_dir = self.circuit_dir.join("target/proof");
        std::fs::create_dir_all(&proof_dir).ok();

        let prove = Command::new(&self.bb_bin)
            .args(["prove", "-b", &self.json_path(), "-w", &self.witness_path(), "-o", "target/proof"])
            .current_dir(&self.circuit_dir)
            .output()
            .map_err(|e| format!("bb prove: {}", e))?;
        if !prove.status.success() {
            return Err(format!("bb prove failed: {} {}",
                String::from_utf8_lossy(&prove.stderr),
                String::from_utf8_lossy(&prove.stdout)));
        }

        // 4. Read outputs
        let proof = std::fs::read(proof_dir.join("proof"))
            .map_err(|e| format!("read proof: {}", e))?;
        let public_inputs = std::fs::read(proof_dir.join("public_inputs"))
            .map_err(|e| format!("read public_inputs: {}", e))?;

        Ok(ProofResult { proof, public_inputs })
    }

    /// Prove full nullifier circuit (entire OPRF chain on secp256k1).
    pub fn prove(
        &self,
        input: &[u8; 32],
        r_bytes: &[u8; 32],
        witness_k: u32,
        witness_z_bytes: &[u8; 32],
        unblinded_x: &[u8; 32],
        unblinded_y: &[u8; 32],
        blinded_x: &[u8; 32],
        blinded_y: &[u8; 32],
        evaluated_x: &[u8; 32],
        evaluated_y: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Result<ProofResult, String> {
        let toml = generate_prover_toml(
            input, r_bytes, witness_k, witness_z_bytes,
            unblinded_x, unblinded_y, blinded_x, blinded_y,
            evaluated_x, evaluated_y, nullifier,
        );
        self.prove_raw(&toml)
    }

    /// Verify a ZK proof.
    pub fn verify(&self, proof: &[u8], public_inputs: &[u8]) -> Result<bool, String> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| format!("tempdir: {}", e))?;

        let proof_path = tmp_dir.path().join("proof");
        let pi_path = tmp_dir.path().join("public_inputs");

        std::fs::write(&proof_path, proof).map_err(|e| format!("write proof: {}", e))?;
        std::fs::write(&pi_path, public_inputs).map_err(|e| format!("write pi: {}", e))?;

        // Ensure VK exists
        let vk_dir = self.circuit_dir.join("target/vk");
        std::fs::create_dir_all(&vk_dir).ok();
        if !vk_dir.join("vk").exists() {
            let vk_out = Command::new(&self.bb_bin)
                .args(["write_vk", "-b", &self.json_path(), "-o", "target/vk"])
                .current_dir(&self.circuit_dir)
                .output()
                .map_err(|e| format!("bb write_vk: {}", e))?;
            if !vk_out.status.success() {
                return Err(format!("bb write_vk failed: {}", String::from_utf8_lossy(&vk_out.stderr)));
            }
        }

        let vk_path = std::fs::canonicalize(vk_dir.join("vk"))
            .map_err(|e| format!("resolve VK path: {}", e))?;

        let out = Command::new(&self.bb_bin)
            .args([
                "verify",
                "-k", &vk_path.to_string_lossy(),
                "-p", &proof_path.to_string_lossy(),
                "-i", &pi_path.to_string_lossy(),
            ])
            .output()
            .map_err(|e| format!("bb verify: {}", e))?;

        if !out.status.success() {
            eprintln!("bb verify failed: {}", String::from_utf8_lossy(&out.stderr));
        }

        Ok(out.status.success())
    }
}
