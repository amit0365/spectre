// Full OPRF Nullifier Circuit -- Non-Native secp256k1
//
// Proves the entire nullifier construction in ZK:
//   1. m = SHA-256(input) -- hash input to field element
//   2. h = map_to_curve(m) -- constraint-friendly increment-and-check
//   3. blinded == h * r -- client blinding
//   4. evaluated == unblinded * r -- proves correct unblinding
//   5. nullifier == SHA-256(input || unblinded) -- nullifier derivation
//
// Uses noir_bigcurve for non-native secp256k1 scalar multiplication.
// Map-to-curve uses ~22 constraints vs ~7,095 for SSWU.

use sha256::digest as sha256;
use bigcurve::BigCurve;
use bigcurve::BigCurveTrait;
use bigcurve::scalar_field::ScalarFieldTrait;
use bigcurve::curves::secp256k1::{
    Secp256k1, Secp256k1Scalar, Secp256k1_Fq, Secp256k1_Fr,
};
use bignum::BigNum;

fn main(
    // Private inputs
    input: [u8; 32],
    r_bytes: [u8; 32],
    witness_k: u32,
    witness_z_bytes: [u8; 32],
    unblinded_x_bytes: [u8; 32],
    unblinded_y_bytes: [u8; 32],
    // Public inputs
    blinded_x_bytes: pub [u8; 32],
    blinded_y_bytes: pub [u8; 32],
    evaluated_x_bytes: pub [u8; 32],
    evaluated_y_bytes: pub [u8; 32],
    nullifier: pub [u8; 32],
) {
    // ---- Step 1: m = SHA-256(input) ----
    let hash = sha256(input);
    let m: Secp256k1_Fq = Secp256k1_Fq::from_be_bytes(hash);

    // ---- Step 2: Map-to-curve witness check (secp256k1: y^2 = x^3 + 7) ----
    // Constraint-friendly: verify (x, y, z, k) such that
    //   x = m * T + k   (T = 256)
    //   y = z^2
    //   y^2 = x^3 + 7
    let t_fq: Secp256k1_Fq = Secp256k1_Fq::from_limbs([256, 0, 0]);

    let k_fq: Secp256k1_Fq = Secp256k1_Fq::from_limbs([witness_k as u128, 0, 0]);

    let z_fq: Secp256k1_Fq = Secp256k1_Fq::from_be_bytes(witness_z_bytes);

    let h_x: Secp256k1_Fq = m * t_fq + k_fq;
    let h_y: Secp256k1_Fq = z_fq * z_fq;

    // Verify on curve: y^2 = x^3 + 7
    let h_x_sq: Secp256k1_Fq = h_x * h_x;
    let h_x_cubed: Secp256k1_Fq = h_x_sq * h_x;
    let seven: Secp256k1_Fq = Secp256k1_Fq::from_limbs([7, 0, 0]);
    let rhs: Secp256k1_Fq = h_x_cubed + seven;
    let lhs: Secp256k1_Fq = h_y * h_y;
    assert(lhs == rhs);

    // ---- Step 3: blinded == h * r ----
    let h: Secp256k1 = BigCurve { x: h_x, y: h_y, is_infinity: false };
    let r_fr: Secp256k1_Fr = Secp256k1_Fr::from_be_bytes(r_bytes);
    let r_scalar: Secp256k1Scalar = Secp256k1Scalar::from_bignum(r_fr);

    let blinded_computed: Secp256k1 = h.mul(r_scalar);

    let blinded_x_fq: Secp256k1_Fq = Secp256k1_Fq::from_be_bytes(blinded_x_bytes);
    let blinded_y_fq: Secp256k1_Fq = Secp256k1_Fq::from_be_bytes(blinded_y_bytes);
    let blinded_expected: Secp256k1 = BigCurve { x: blinded_x_fq, y: blinded_y_fq, is_infinity: false };
    assert(blinded_computed == blinded_expected);

    // ---- Step 4: evaluated == unblinded * r ----
    let unblinded_x_fq: Secp256k1_Fq = Secp256k1_Fq::from_be_bytes(unblinded_x_bytes);
    let unblinded_y_fq: Secp256k1_Fq = Secp256k1_Fq::from_be_bytes(unblinded_y_bytes);
    let unblinded: Secp256k1 = BigCurve { x: unblinded_x_fq, y: unblinded_y_fq, is_infinity: false };

    let eval_computed: Secp256k1 = unblinded.mul(r_scalar);

    let evaluated_x_fq: Secp256k1_Fq = Secp256k1_Fq::from_be_bytes(evaluated_x_bytes);
    let evaluated_y_fq: Secp256k1_Fq = Secp256k1_Fq::from_be_bytes(evaluated_y_bytes);
    let evaluated_expected: Secp256k1 = BigCurve { x: evaluated_x_fq, y: evaluated_y_fq, is_infinity: false };
    assert(eval_computed == evaluated_expected);

    // ---- Step 5: nullifier == SHA-256(input || unblinded_x || unblinded_y) ----
    let ub_x_be: [u8; 32] = unblinded_x_fq.to_be_bytes();
    let ub_y_be: [u8; 32] = unblinded_y_fq.to_be_bytes();
    let mut preimage: [u8; 96] = [0; 96];
    for i in 0..32 {
        preimage[i] = input[i];
    }
    for i in 0..32 {
        preimage[32 + i] = ub_x_be[i];
    }
    for i in 0..32 {
        preimage[64 + i] = ub_y_be[i];
    }
    let computed_nullifier = sha256(preimage);
    assert(computed_nullifier == nullifier);
}
