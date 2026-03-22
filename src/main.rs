use std::collections::HashSet;

use k256::elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint};
use oprf_nullifier::{
    hash_to_curve::{
        hash_to_curve_with_witness, hash_to_field, verify_map_to_curve_relation,
        DEFAULT_TWEAK_BOUND,
    },
    OprfClient, OprfServer,
};

fn main() {
    println!();
    println!("================================================================");
    println!("  OPRF Nullifier Service");
    println!("  Using constraint-friendly map-to-curve on secp256k1");
    println!("  (Groth, Malvai, Miller, Zhang)");
    println!("================================================================");
    println!();

    // ── Setup ────────────────────────────────────────────────
    let server = OprfServer::random();
    println!("  Server started with random OPRF key.");
    println!(
        "  Public key: {}",
        hex::encode(
            server
                .public_key()
                .to_affine()
                .to_encoded_point(true)
                .as_bytes()
        )
    );
    println!();

    // ── Protocol flow ────────────────────────────────────────
    println!("-- OPRF Protocol Flow ----------------------------------------------");
    println!();

    let input = b"alice@example.com";
    println!("  Client input: \"{}\"", std::str::from_utf8(input).unwrap());
    println!();

    // Step 1: Client blinds
    let req = OprfClient::blind(input);
    println!("  1. Client: h = hash_to_curve(SHA-256(input))");
    println!("     witness.tweak = {}", req.witness.tweak);
    println!("     witness.z     = 0x{}...", &hex::encode(&req.witness.z)[..16]);
    println!(
        "     blinded       = 0x{}...",
        &hex::encode(req.blinded.to_affine().to_encoded_point(true).as_bytes())[..20]
    );
    println!();

    // Verify the witness
    let (m, _) = hash_to_field(input);
    let h_affine = req.h.to_affine();
    let witness_valid = verify_map_to_curve_relation(&m, &h_affine, &req.witness, DEFAULT_TWEAK_BOUND);
    println!("  2. Witness verification: {}", if witness_valid { "PASS" } else { "FAIL" });
    println!("     x = m * {} + {}", DEFAULT_TWEAK_BOUND, req.witness.tweak);
    println!("     y = z^2       (checked)");
    println!("     y^2 = x^3 + 7 (checked)");
    println!();

    // Step 2: Server evaluates (sees only the blinded point)
    let evaluated = server.evaluate(&req.blinded);
    println!("  3. Server: evaluated = blinded^k  (server never sees input)");
    println!(
        "     evaluated = 0x{}...",
        &hex::encode(evaluated.to_affine().to_encoded_point(true).as_bytes())[..20]
    );
    println!();

    // Step 3: Client unblinds and derives nullifier
    let output = OprfClient::finalize(input, &evaluated, &req.blinding_factor);
    println!("  4. Client: unblind + finalize");
    println!("     nullifier = 0x{}", hex::encode(&output.nullifier));
    println!();

    // ── Determinism check ────────────────────────────────────
    println!("-- Determinism Check -----------------------------------------------");
    println!();

    let req2 = OprfClient::blind(input);
    let eval2 = server.evaluate(&req2.blinded);
    let out2 = OprfClient::finalize(input, &eval2, &req2.blinding_factor);

    println!("  Same input, new blinding factor:");
    println!("  nullifier_1 = 0x{}", hex::encode(&output.nullifier));
    println!("  nullifier_2 = 0x{}", hex::encode(&out2.nullifier));
    println!(
        "  Match: {}",
        if output.nullifier == out2.nullifier {
            "YES (deterministic)"
        } else {
            "NO (BUG!)"
        }
    );
    println!();

    // ── Different input → different nullifier ────────────────
    println!("-- Different Inputs ------------------------------------------------");
    println!();

    let users = [
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com",
        "alice@example.com", // duplicate
    ];
    let mut nullifier_set: HashSet<[u8; 32]> = HashSet::new();
    let mut duplicate_detected = false;

    for user in &users {
        let req = OprfClient::blind(user.as_bytes());
        let eval = server.evaluate(&req.blinded);
        let out = OprfClient::finalize(user.as_bytes(), &eval, &req.blinding_factor);

        let is_new = nullifier_set.insert(out.nullifier);
        let status = if is_new { "new" } else { "DUPLICATE" };
        if !is_new {
            duplicate_detected = true;
        }
        println!(
            "  {:<25} → 0x{}...  [{}]",
            user,
            &hex::encode(&out.nullifier)[..16],
            status
        );
    }
    println!();
    if duplicate_detected {
        println!("  Sybil detected: same email → same nullifier. Duplicate rejected.");
    }
    println!();

    // ── ZK proof data ────────────────────────────────────────
    println!("-- Noir Circuit Inputs (for ZK proof) ------------------------------");
    println!();

    let req = OprfClient::blind(b"alice@example.com");
    let h_affine = req.h.to_affine();
    let x_bytes: Vec<u8> = h_affine.x().as_slice().to_vec();
    let encoded = h_affine.to_encoded_point(false);
    let y_bytes: Vec<u8> = encoded.y().unwrap().as_slice().to_vec();

    println!("  # Prover.toml — private witness for hash-to-curve verification");
    println!("  m_hash = \"0x{}\"", hex::encode(&req.m_bytes));
    println!("  x      = \"0x{}\"", hex::encode(&x_bytes));
    println!("  y      = \"0x{}\"", hex::encode(&y_bytes));
    println!("  k      = {}", req.witness.tweak);
    println!("  z      = \"0x{}\"", hex::encode(&req.witness.z));
    println!();
    println!("  Circuit verifies (~22 constraints):");
    println!("    assert(x == m_hash * 256 + k)");
    println!("    assert(y == z * z)");
    println!("    assert(y * y == x * x * x + 7)");
    println!();

    // ── Constraint comparison ────────────────────────────────
    println!("-- Circuit Cost Comparison -----------------------------------------");
    println!();
    println!("  {:<35} {:>12} {:>12}", "Component", "SSWU", "Ours");
    println!("  {:<35} {:>12} {:>12}", "---", "---", "---");
    println!("  {:<35} {:>12} {:>12}", "SHA-256(input)", "~25,000", "~25,000");
    println!(
        "  {:<35} {:>12} {:>12}",
        "map-to-curve (non-native)", "~250,000", "~2,500"
    );
    println!("  {:<35} {:>12} {:>12}", "Policy check", "varies", "varies");
    println!("  {:<35} {:>12} {:>12}", "---", "---", "---");
    println!("  {:<35} {:>12} {:>12}", "TOTAL", "~275,000", "~27,500");
    println!("  {:<35} {:>12} {:>12}", "Reduction", "", "10x");
    println!();
    println!("  The ZK circuit proves: \"I correctly computed h = hash_to_curve(x)");
    println!("  and x satisfies the required policy.\" No EC scalar muls needed —");
    println!("  blinding/unblinding happens off-circuit.");
    println!();
    println!("================================================================");
}
