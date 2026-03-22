//! Grumpkin elliptic curve point arithmetic over BN254 scalar field Fr.
//!
//! Grumpkin: y^2 = x^3 - 17 over Fr
//! Fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617

use k256::sha2::{Digest, Sha256};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::hash_to_curve_grumpkin::{fr_modulus, hash_to_field_grumpkin, map_to_curve_grumpkin, DEFAULT_TWEAK_BOUND};

/// BN254 base field order (= Grumpkin scalar field / group order).
/// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
pub fn grumpkin_order() -> BigUint {
    BigUint::parse_bytes(
        b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
        16,
    )
    .unwrap()
}

#[derive(Clone, Debug)]
pub struct GrumpkinPoint {
    pub x: BigUint,
    pub y: BigUint,
    pub is_infinity: bool,
}

impl GrumpkinPoint {
    pub fn infinity() -> Self {
        GrumpkinPoint {
            x: BigUint::zero(),
            y: BigUint::zero(),
            is_infinity: true,
        }
    }

    pub fn new(x: BigUint, y: BigUint) -> Self {
        GrumpkinPoint { x, y, is_infinity: false }
    }

    /// Point addition on Grumpkin.
    pub fn add(&self, other: &Self) -> Self {
        let p = fr_modulus();
        if self.is_infinity { return other.clone(); }
        if other.is_infinity { return self.clone(); }

        if self.x == other.x {
            if self.y == other.y && !self.y.is_zero() {
                return self.double();
            }
            return GrumpkinPoint::infinity();
        }

        // lambda = (y2 - y1) / (x2 - x1) mod p
        let dy = if other.y >= self.y {
            (&other.y - &self.y) % &p
        } else {
            (&p + &other.y - &self.y) % &p
        };
        let dx = if other.x >= self.x {
            (&other.x - &self.x) % &p
        } else {
            (&p + &other.x - &self.x) % &p
        };
        let dx_inv = mod_inv(&dx, &p);
        let lambda = (&dy * &dx_inv) % &p;

        // x3 = lambda^2 - x1 - x2
        let lambda_sq = (&lambda * &lambda) % &p;
        let x3 = (&p + &p + &lambda_sq - &self.x - &other.x) % &p;

        // y3 = lambda * (x1 - x3) - y1
        let diff = if self.x >= x3 {
            (&self.x - &x3) % &p
        } else {
            (&p + &self.x - &x3) % &p
        };
        let y3 = (&p + (&lambda * &diff) % &p - &self.y) % &p;

        GrumpkinPoint::new(x3, y3)
    }

    /// Point doubling on Grumpkin (a = 0).
    pub fn double(&self) -> Self {
        if self.is_infinity || self.y.is_zero() {
            return GrumpkinPoint::infinity();
        }
        let p = fr_modulus();

        // lambda = 3*x^2 / (2*y)  (since a=0 for Grumpkin)
        let x_sq = (&self.x * &self.x) % &p;
        let num = (BigUint::from(3u32) * &x_sq) % &p;
        let den = (BigUint::from(2u32) * &self.y) % &p;
        let den_inv = mod_inv(&den, &p);
        let lambda = (&num * &den_inv) % &p;

        let lambda_sq = (&lambda * &lambda) % &p;
        let x3 = (&p + &p + &lambda_sq - &self.x - &self.x) % &p;

        let diff = if self.x >= x3 {
            (&self.x - &x3) % &p
        } else {
            (&p + &self.x - &x3) % &p
        };
        let y3 = (&p + (&lambda * &diff) % &p - &self.y) % &p;

        GrumpkinPoint::new(x3, y3)
    }

    /// Double-and-add scalar multiplication.
    pub fn scalar_mul(&self, scalar: &BigUint) -> Self {
        if scalar.is_zero() || self.is_infinity {
            return GrumpkinPoint::infinity();
        }

        let mut result = GrumpkinPoint::infinity();
        let mut base = self.clone();
        let mut s = scalar.clone();

        while !s.is_zero() {
            if &s % BigUint::from(2u32) == BigUint::one() {
                result = result.add(&base);
            }
            base = base.double();
            s >>= 1;
        }
        result
    }

    /// Verify point is on Grumpkin: y^2 = x^3 - 17 mod Fr.
    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity { return true; }
        let p = fr_modulus();
        let y_sq = (&self.y * &self.y) % &p;
        let x_cubed = (&self.x * &self.x % &p) * &self.x % &p;
        let rhs = (&p + &x_cubed - BigUint::from(17u32)) % &p;
        y_sq == rhs
    }

    pub fn x_bytes(&self) -> [u8; 32] {
        biguint_to_32_bytes(&self.x)
    }

    pub fn y_bytes(&self) -> [u8; 32] {
        biguint_to_32_bytes(&self.y)
    }
}

fn mod_inv(a: &BigUint, p: &BigUint) -> BigUint {
    // a^(p-2) mod p (Fermat's little theorem)
    let exp = p - BigUint::from(2u32);
    a.modpow(&exp, p)
}

fn biguint_to_32_bytes(n: &BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    out
}

/// Full nullifier witness for the Grumpkin native circuit.
#[derive(Clone, Debug)]
pub struct FullNullifierWitness {
    pub input: [u8; 32],
    pub r_lo: [u8; 32],
    pub r_hi: [u8; 32],
    pub witness_k: u32,
    pub witness_z: [u8; 32],
    pub unblinded_x: [u8; 32],
    pub unblinded_y: [u8; 32],
    pub blinded_x: [u8; 32],
    pub blinded_y: [u8; 32],
    pub evaluated_x: [u8; 32],
    pub evaluated_y: [u8; 32],
    pub nullifier: [u8; 32],
}

/// Generate full nullifier witness for the native Grumpkin circuit.
///
/// Performs the entire OPRF protocol:
///   1. m = SHA-256(input) mod Fr
///   2. h = map_to_curve(m) on Grumpkin
///   3. blinded = h * r
///   4. evaluated = blinded * server_key
///   5. unblinded = evaluated * r^(-1)
///   6. nullifier = SHA-256(input || unblinded_x || unblinded_y)
pub fn generate_full_witness(
    input: &[u8; 32],
    server_key: &BigUint,
) -> FullNullifierWitness {
    let fr = fr_modulus();
    let grumpkin_n = grumpkin_order();

    // Step 1: m = SHA-256(input) mod Fr
    let (m, _m_bytes) = hash_to_field_grumpkin(input);

    // Step 2: map_to_curve
    let mtc_witness = map_to_curve_grumpkin(&m, DEFAULT_TWEAK_BOUND)
        .expect("map_to_curve should succeed");
    let h = GrumpkinPoint::new(
        BigUint::from_bytes_be(&mtc_witness.x),
        BigUint::from_bytes_be(&mtc_witness.y),
    );
    assert!(h.is_on_curve(), "h must be on curve");

    // Step 3: blinding factor r (random, but for deterministic testing use a fixed value)
    // r must be in [1, grumpkin_order)
    let r_bytes: [u8; 32] = {
        let hash = Sha256::digest(b"blinding_factor_seed");
        let mut buf = [0u8; 32];
        buf.copy_from_slice(hash.as_ref());
        buf
    };
    let r = BigUint::from_bytes_be(&r_bytes) % &grumpkin_n;
    let r = if r.is_zero() { BigUint::one() } else { r };

    // Split r into lo (128 bits) and hi (128 bits) for EmbeddedCurveScalar
    let r_lo_val = &r % (BigUint::one() << 128);
    let r_hi_val = &r >> 128;

    // blinded = h * r
    let blinded = h.scalar_mul(&r);
    assert!(blinded.is_on_curve(), "blinded must be on curve");

    // Step 4: server evaluates: evaluated = blinded * server_key
    let evaluated = blinded.scalar_mul(server_key);
    assert!(evaluated.is_on_curve(), "evaluated must be on curve");

    // Step 5: unblinded = evaluated * r^(-1)
    let r_inv = mod_inv(&r, &grumpkin_n);
    let unblinded = evaluated.scalar_mul(&r_inv);
    assert!(unblinded.is_on_curve(), "unblinded must be on curve");

    // Verify: unblinded should equal h * server_key
    let h_k = h.scalar_mul(server_key);
    assert_eq!(unblinded.x, h_k.x, "unblinding must give h^k");
    assert_eq!(unblinded.y, h_k.y, "unblinding must give h^k");

    // Step 6: nullifier = SHA-256(input || unblinded_x_be || unblinded_y_be)
    let ub_x_bytes = biguint_to_32_bytes(&unblinded.x);
    let ub_y_bytes = biguint_to_32_bytes(&unblinded.y);
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.update(&ub_x_bytes);
    hasher.update(&ub_y_bytes);
    let null_hash = hasher.finalize();
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(null_hash.as_ref());

    FullNullifierWitness {
        input: *input,
        r_lo: biguint_to_32_bytes(&r_lo_val),
        r_hi: biguint_to_32_bytes(&r_hi_val),
        witness_k: mtc_witness.tweak,
        witness_z: mtc_witness.z,
        unblinded_x: ub_x_bytes,
        unblinded_y: ub_y_bytes,
        blinded_x: biguint_to_32_bytes(&blinded.x),
        blinded_y: biguint_to_32_bytes(&blinded.y),
        evaluated_x: biguint_to_32_bytes(&evaluated.x),
        evaluated_y: biguint_to_32_bytes(&evaluated.y),
        nullifier,
    }
}

/// Generate Prover.toml for the full nullifier circuit.
pub fn generate_full_prover_toml(w: &FullNullifierWitness) -> String {
    let be = |bytes: &[u8; 32]| -> String {
        format!("\"0x{}\"", hex::encode(bytes))
    };

    let mut toml = String::new();

    // input: [u8; 32]
    toml.push_str("input = [");
    for (i, b) in w.input.iter().enumerate() {
        if i > 0 { toml.push_str(", "); }
        toml.push_str(&format!("{}", b));
    }
    toml.push_str("]\n");

    // Scalar fields
    toml.push_str(&format!("r_lo = {}\n", be(&w.r_lo)));
    toml.push_str(&format!("r_hi = {}\n", be(&w.r_hi)));
    toml.push_str(&format!("witness_k = {}\n", be(&biguint_to_32_bytes(&BigUint::from(w.witness_k)))));
    toml.push_str(&format!("witness_z = {}\n", be(&w.witness_z)));
    toml.push_str(&format!("unblinded_x = {}\n", be(&w.unblinded_x)));
    toml.push_str(&format!("unblinded_y = {}\n", be(&w.unblinded_y)));
    toml.push_str(&format!("blinded_x = {}\n", be(&w.blinded_x)));
    toml.push_str(&format!("blinded_y = {}\n", be(&w.blinded_y)));
    toml.push_str(&format!("evaluated_x = {}\n", be(&w.evaluated_x)));
    toml.push_str(&format!("evaluated_y = {}\n", be(&w.evaluated_y)));

    // nullifier: [u8; 32]
    toml.push_str("nullifier = [");
    for (i, b) in w.nullifier.iter().enumerate() {
        if i > 0 { toml.push_str(", "); }
        toml.push_str(&format!("{}", b));
    }
    toml.push_str("]\n");

    toml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grumpkin_point_on_curve() {
        // From the known test: m=7, T=256, k=0 → x=1792
        let x = BigUint::from(1792u32);
        let y = BigUint::parse_bytes(
            b"2222603532014808061213222263845635574143735707039159930479525957984581958699",
            10,
        ).unwrap();
        let pt = GrumpkinPoint::new(x, y);
        assert!(pt.is_on_curve());
    }

    #[test]
    fn test_grumpkin_scalar_mul_identity() {
        let x = BigUint::from(1792u32);
        let y = BigUint::parse_bytes(
            b"2222603532014808061213222263845635574143735707039159930479525957984581958699",
            10,
        ).unwrap();
        let pt = GrumpkinPoint::new(x, y);

        // 1 * P = P
        let result = pt.scalar_mul(&BigUint::one());
        assert_eq!(result.x, pt.x);
        assert_eq!(result.y, pt.y);
    }

    #[test]
    fn test_grumpkin_double_add() {
        let x = BigUint::from(1792u32);
        let y = BigUint::parse_bytes(
            b"2222603532014808061213222263845635574143735707039159930479525957984581958699",
            10,
        ).unwrap();
        let pt = GrumpkinPoint::new(x, y);

        // 2P = P + P = P.double()
        let double = pt.double();
        let add = pt.add(&pt);
        assert_eq!(double.x, add.x);
        assert_eq!(double.y, add.y);
        assert!(double.is_on_curve());
    }

    #[test]
    fn test_full_witness_generation() {
        let input = [0u8; 32];
        let server_key = BigUint::from(42u32);
        let witness = generate_full_witness(&input, &server_key);

        // Check nullifier is non-zero
        assert_ne!(witness.nullifier, [0u8; 32]);

        // Generate TOML and check it's non-empty
        let toml = generate_full_prover_toml(&witness);
        assert!(toml.contains("input"));
        assert!(toml.contains("r_lo"));
        assert!(toml.contains("nullifier"));
        eprintln!("Generated Prover.toml:\n{}", toml);
    }
}
