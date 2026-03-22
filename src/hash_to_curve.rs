//! Constraint-friendly map-to-curve on secp256k1.
//!
//! Implements the increment-and-check relation from:
//! "Constraint-Friendly Map-to-Elliptic-Curve-Group Relations and Their Applications"
//! — Groth, Malvai, Miller, Zhang
//!
//! Replaces the ~7,095-constraint SSWU gadget with ~22 constraints.

use k256::{
    elliptic_curve::{
        bigint::ArrayEncoding,
        point::AffineCoordinates,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    sha2::{Digest, Sha256},
    AffinePoint, EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, U256,
};

/// Default tweak bound T = 256 (recommended by paper).
pub const DEFAULT_TWEAK_BOUND: u32 = 256;

/// secp256k1 curve constant b = 7 (y² = x³ + 7).
const COEFF_B: FieldElement = FieldElement::from_u64(7);

/// secp256k1 field modulus p.
const SECP256K1_P: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

/// Witness for the increment-and-check map-to-curve relation.
///
/// Given field element `m` and tweak bound `T`, witness `(k, z)` satisfies:
/// 1. `k ∈ [0, T)`
/// 2. `x = m · T + k`
/// 3. `y = z²`  (y is a quadratic residue)
/// 4. `y² = x³ + 7`  (point is on secp256k1)
#[derive(Clone, Debug)]
pub struct MapToCurveWitness {
    /// The tweak `k ∈ [0, T)`.
    pub tweak: u32,
    /// The square-root witness `z` such that `z² = y`, big-endian 32 bytes.
    pub z: [u8; 32],
}

// ── Field helpers ───────────────────────────────────────────────

/// Reduces a 32-byte big-endian value to a field element in Fq.
/// Handles the rare case where value ≥ p by subtracting p.
fn reduce_to_field_element(bytes: &[u8; 32]) -> FieldElement {
    let fb = FieldBytes::from(*bytes);
    Option::from(FieldElement::from_bytes(&fb)).unwrap_or_else(|| {
        let val = U256::from_be_byte_array(fb);
        let reduced = val.wrapping_sub(&SECP256K1_P);
        Option::from(FieldElement::from_bytes(&reduced.to_be_byte_array()))
            .expect("reduced value must be < p")
    })
}

fn fe_to_bytes(fe: &FieldElement) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(fe.to_bytes().as_ref());
    out
}

fn affine_y(point: &AffinePoint) -> FieldElement {
    let encoded = point.to_encoded_point(false);
    Option::from(FieldElement::from_bytes(
        encoded.y().expect("non-identity point has y"),
    ))
    .expect("y bytes are a valid field element")
}

fn affine_from_xy(x: &FieldElement, y: &FieldElement) -> AffinePoint {
    let encoded = EncodedPoint::from_affine_coordinates(&x.to_bytes(), &y.to_bytes(), false);
    Option::from(AffinePoint::from_encoded_point(&encoded)).expect("point must be on curve")
}

// ── Core algorithm ──────────────────────────────────────────────

/// Increment-and-check constructor (Paper Fig. 1).
///
/// Finds `(x, y)` on secp256k1 with witness `(k, z)` such that
/// `x = m·T + k`, `z² = y`, and `y² = x³ + 7`.
///
/// Expected ~2 iterations.
pub fn map_to_curve_construct(
    m: &FieldElement,
    tweak_bound: u32,
) -> Option<(AffinePoint, MapToCurveWitness)> {
    let t_fe = FieldElement::from(tweak_bound as u64);
    let base = (m * &t_fe).normalize();

    for k in 0..tweak_bound {
        let k_fe = FieldElement::from(k as u64);
        let x = (base + k_fe).normalize();

        // f(x) = x³ + 7
        let f_x = (x.square() * &x + COEFF_B).normalize();

        // Try y = √f(x)
        let y_opt: Option<FieldElement> = f_x.sqrt().into();
        if let Some(y_raw) = y_opt {
            let y = y_raw.normalize();

            // Try z = √y (y must be QR)
            let z_opt: Option<FieldElement> = y.sqrt().into();
            if let Some(z_raw) = z_opt {
                let z = z_raw.normalize();
                let point = affine_from_xy(&x, &y);
                return Some((
                    point,
                    MapToCurveWitness {
                        tweak: k,
                        z: fe_to_bytes(&z),
                    },
                ));
            }

            // Try −y
            let neg_y = (-y).normalize();
            let z_neg_opt: Option<FieldElement> = neg_y.sqrt().into();
            if let Some(z_raw) = z_neg_opt {
                let z = z_raw.normalize();
                let point = affine_from_xy(&x, &neg_y);
                return Some((
                    point,
                    MapToCurveWitness {
                        tweak: k,
                        z: fe_to_bytes(&z),
                    },
                ));
            }
        }
    }
    None
}

/// Verifies all four RM2G constraints.
pub fn verify_map_to_curve_relation(
    m: &FieldElement,
    point: &AffinePoint,
    witness: &MapToCurveWitness,
    tweak_bound: u32,
) -> bool {
    if witness.tweak >= tweak_bound {
        return false;
    }

    let t_fe = FieldElement::from(tweak_bound as u64);
    let k_fe = FieldElement::from(witness.tweak as u64);
    let expected_x = (m * &t_fe + k_fe).normalize();

    let x = point.x();
    if expected_x.to_bytes() != x {
        return false;
    }

    let y = affine_y(point);
    let z: FieldElement = match Option::from(FieldElement::from_bytes(&FieldBytes::from(witness.z)))
    {
        Some(fe) => fe,
        None => return false,
    };

    let z_sq = (z * &z).normalize();
    if z_sq.to_bytes() != y.to_bytes() {
        return false;
    }

    let y_sq = (y * &y).normalize();
    let x_fe: FieldElement =
        match Option::from(FieldElement::from_bytes(&x)) {
            Some(fe) => fe,
            None => return false,
        };
    let rhs = (x_fe.square() * &x_fe + COEFF_B).normalize();

    y_sq.to_bytes() == rhs.to_bytes()
}

/// Full hash-to-curve: SHA-256(input) → field element → witness constructor.
///
/// This is the OPRF variant: hashes just the input (no public key).
pub fn hash_to_curve_with_witness(
    input: &[u8],
    tweak_bound: u32,
) -> Option<(ProjectivePoint, MapToCurveWitness)> {
    let hash = Sha256::digest(input);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(hash.as_ref());
    let m = reduce_to_field_element(&hash_bytes);

    let (affine, witness) = map_to_curve_construct(&m, tweak_bound)?;
    Some((ProjectivePoint::from(affine), witness))
}

/// Returns the field element m = SHA-256(input) mod q.
/// Useful for passing to the Noir circuit as a public input.
pub fn hash_to_field(input: &[u8]) -> (FieldElement, [u8; 32]) {
    let hash = Sha256::digest(input);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(hash.as_ref());
    let m = reduce_to_field_element(&hash_bytes);
    (m, fe_to_bytes(&m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_and_verify() {
        let m = FieldElement::from(42u64);
        let (point, witness) = map_to_curve_construct(&m, DEFAULT_TWEAK_BOUND).unwrap();
        assert!(verify_map_to_curve_relation(
            &m,
            &point,
            &witness,
            DEFAULT_TWEAK_BOUND
        ));
    }

    #[test]
    fn test_tampered_witness_rejected() {
        let m = FieldElement::from(42u64);
        let (point, witness) = map_to_curve_construct(&m, DEFAULT_TWEAK_BOUND).unwrap();
        let mut bad_z = witness.z;
        bad_z[31] ^= 1;
        let bad = MapToCurveWitness {
            tweak: witness.tweak,
            z: bad_z,
        };
        assert!(!verify_map_to_curve_relation(
            &m, &point, &bad, DEFAULT_TWEAK_BOUND
        ));
    }

    #[test]
    fn test_hash_to_curve_deterministic() {
        let (p1, w1) = hash_to_curve_with_witness(b"hello", DEFAULT_TWEAK_BOUND).unwrap();
        let (p2, w2) = hash_to_curve_with_witness(b"hello", DEFAULT_TWEAK_BOUND).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(w1.tweak, w2.tweak);
        assert_eq!(w1.z, w2.z);
    }

    #[test]
    fn test_different_inputs_different_points() {
        let (p1, _) = hash_to_curve_with_witness(b"alice@example.com", DEFAULT_TWEAK_BOUND).unwrap();
        let (p2, _) = hash_to_curve_with_witness(b"bob@example.com", DEFAULT_TWEAK_BOUND).unwrap();
        assert_ne!(p1, p2);
    }
}
