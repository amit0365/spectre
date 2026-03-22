//! End-to-end test for the full non-native nullifier proof.
//!
//! Generates witness → writes Prover.toml → nargo execute → bb prove → bb verify

use oprf_nullifier::noir_prover::compute_witness;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_full_nonnative_witness_and_execute() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let nargo = PathBuf::from(format!("{}/.nargo/bin/nargo", home));
    let bb = PathBuf::from(format!("{}/.bb/bb", home));
    let circuit_dir = PathBuf::from("noir-circuit");

    // Check nargo exists
    if !nargo.exists() {
        eprintln!("nargo not found, skipping test");
        return;
    }

    // Generate witness
    let input = [0u8; 32];
    let server_key = k256::NonZeroScalar::random(&mut rand_core::OsRng);
    let (toml_content, nullifier) = compute_witness(&input, &server_key);

    eprintln!("Generated Prover.toml ({} bytes)", toml_content.len());
    eprintln!("Nullifier: {}", hex::encode(&nullifier));

    // Write Prover.toml
    std::fs::write(circuit_dir.join("Prover.toml"), &toml_content)
        .expect("write Prover.toml");

    // nargo execute
    eprintln!("Running nargo execute...");
    let exec = Command::new(&nargo)
        .arg("execute")
        .current_dir(&circuit_dir)
        .output()
        .expect("nargo execute");

    if !exec.status.success() {
        let stderr = String::from_utf8_lossy(&exec.stderr);
        panic!("nargo execute failed:\n{}", stderr);
    }
    eprintln!("nargo execute succeeded!");

    // bb prove
    eprintln!("Running bb prove...");
    let proof_dir = circuit_dir.join("target/proof");
    std::fs::create_dir_all(&proof_dir).ok();

    let artifact = "oprf_nullifier_full_nonnative";
    let prove = Command::new(&bb)
        .args([
            "prove",
            "-b", &format!("target/{}.json", artifact),
            "-w", &format!("target/{}.gz", artifact),
            "-o", "target/proof",
        ])
        .current_dir(&circuit_dir)
        .output()
        .expect("bb prove");

    if !prove.status.success() {
        let stderr = String::from_utf8_lossy(&prove.stderr);
        let stdout = String::from_utf8_lossy(&prove.stdout);
        panic!("bb prove failed:\n{}\n{}", stderr, stdout);
    }
    eprintln!("bb prove succeeded!");

    // Read proof
    let proof = std::fs::read(proof_dir.join("proof")).expect("read proof");
    eprintln!("Proof size: {} bytes", proof.len());

    // bb verify
    eprintln!("Running bb verify...");
    let vk_dir = circuit_dir.join("target/vk");
    std::fs::create_dir_all(&vk_dir).ok();

    // Generate VK if needed
    if !vk_dir.join("vk").exists() {
        let vk_out = Command::new(&bb)
            .args(["write_vk", "-b", &format!("target/{}.json", artifact), "-o", "target/vk"])
            .current_dir(&circuit_dir)
            .output()
            .expect("bb write_vk");
        assert!(vk_out.status.success(), "write_vk failed");
    }

    let vk_path = std::fs::canonicalize(vk_dir.join("vk")).expect("vk path");
    let proof_path = std::fs::canonicalize(proof_dir.join("proof")).expect("proof path");
    let pi_path = std::fs::canonicalize(proof_dir.join("public_inputs")).expect("pi path");

    let verify = Command::new(&bb)
        .args([
            "verify",
            "-k", &vk_path.to_string_lossy(),
            "-p", &proof_path.to_string_lossy(),
            "-i", &pi_path.to_string_lossy(),
        ])
        .output()
        .expect("bb verify");

    if !verify.status.success() {
        let stderr = String::from_utf8_lossy(&verify.stderr);
        panic!("bb verify failed:\n{}", stderr);
    }
    eprintln!("bb verify succeeded! Full non-native nullifier proof verified.");
}
