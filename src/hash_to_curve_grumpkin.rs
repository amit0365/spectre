//! Constraint-friendly map-to-curve on Grumpkin (native to BN254).
//!
//! Grumpkin: y^2 = x^3 - 17 over BN254's scalar field Fr.
//! Since Fr is Noir's native field, all circuit arithmetic is native.

use k256::sha2::{Digest, Sha256};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

/// BN254 scalar field order (= Grumpkin base field).
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub fn fr_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        16,
    )
    .unwrap()
}

pub const DEFAULT_TWEAK_BOUND: u32 = 256;

#[derive(Clone, Debug)]
pub struct GrumpkinWitness {
    pub tweak: u32,
    /// z such that z^2 = y (mod r), big-endian 32 bytes
    pub z: [u8; 32],
    /// x coordinate, big-endian 32 bytes
    pub x: [u8; 32],
    /// y coordinate, big-endian 32 bytes
    pub y: [u8; 32],
}

/// Modular exponentiation: base^exp mod modulus
fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

/// Tonelli-Shanks square root mod p.
/// Returns Some(sqrt) if n is a QR, None otherwise.
fn mod_sqrt(n: &BigUint, p: &BigUint) -> Option<BigUint> {
    if n.is_zero() {
        return Some(BigUint::zero());
    }

    // Euler criterion: n^((p-1)/2) mod p == 1
    let one = BigUint::one();
    let p_minus_1 = p - &one;
    let half = &p_minus_1 / BigUint::from(2u32);
    if mod_pow(n, &half, p) != one {
        return None;
    }

    // Factor p-1 = Q * 2^S
    let mut q = p_minus_1.clone();
    let mut s: u32 = 0;
    while q.is_even() {
        q /= BigUint::from(2u32);
        s += 1;
    }

    if s == 1 {
        // p ≡ 3 (mod 4)
        let exp = (p + &one) / BigUint::from(4u32);
        return Some(mod_pow(n, &exp, p));
    }

    // Find a non-residue z
    let mut z_val = BigUint::from(2u32);
    while mod_pow(&z_val, &half, p) != p_minus_1 {
        z_val += &one;
    }

    let mut m_val = s;
    let mut c = mod_pow(&z_val, &q, p);
    let mut t = mod_pow(n, &q, p);
    let mut r_val = mod_pow(n, &((&q + &one) / BigUint::from(2u32)), p);

    loop {
        if t.is_one() {
            return Some(r_val);
        }

        // Find least i such that t^(2^i) = 1
        let mut i = 1u32;
        let mut tmp = (&t * &t) % p;
        while tmp != one {
            tmp = (&tmp * &tmp) % p;
            i += 1;
        }

        let exp = BigUint::one() << (m_val - i - 1) as u64;
        let b = mod_pow(&c, &exp, p);
        m_val = i;
        c = (&b * &b) % p;
        t = (&t * &c) % p;
        r_val = (&r_val * &b) % p;
    }
}

fn biguint_to_32_bytes(n: &BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    out
}

/// Hash input to a field element m in Fr.
pub fn hash_to_field_grumpkin(input: &[u8]) -> (BigUint, [u8; 32]) {
    let hash = Sha256::digest(input);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(hash.as_ref());
    let m = BigUint::from_bytes_be(&hash_bytes) % fr_modulus();
    let m_bytes = biguint_to_32_bytes(&m);
    (m, m_bytes)
}

/// Increment-and-check map-to-curve on Grumpkin.
///
/// Grumpkin: y^2 = x^3 - 17 over Fr.
/// Finds (x, y) with witness (k, z) such that:
///   x = m * T + k,  z^2 = y,  y^2 = x^3 - 17
pub fn map_to_curve_grumpkin(
    m: &BigUint,
    tweak_bound: u32,
) -> Option<GrumpkinWitness> {
    let p = fr_modulus();
    let t = BigUint::from(tweak_bound);
    let base = (m * &t) % &p;
    let b_coeff = BigUint::from(17u32);

    for k in 0..tweak_bound {
        let x = (&base + BigUint::from(k)) % &p;

        // f(x) = x^3 - 17 mod p
        let x_sq = (&x * &x) % &p;
        let x_cubed = (&x_sq * &x) % &p;
        let f_x = if x_cubed >= b_coeff {
            (&x_cubed - &b_coeff) % &p
        } else {
            (&p + &x_cubed - &b_coeff) % &p
        };

        // Need y = sqrt(f_x) AND z = sqrt(y)
        if let Some(y) = mod_sqrt(&f_x, &p) {
            // Try y
            if let Some(z) = mod_sqrt(&y, &p) {
                return Some(GrumpkinWitness {
                    tweak: k,
                    z: biguint_to_32_bytes(&z),
                    x: biguint_to_32_bytes(&x),
                    y: biguint_to_32_bytes(&y),
                });
            }
            // Try -y
            let neg_y = (&p - &y) % &p;
            if let Some(z) = mod_sqrt(&neg_y, &p) {
                return Some(GrumpkinWitness {
                    tweak: k,
                    z: biguint_to_32_bytes(&z),
                    x: biguint_to_32_bytes(&x),
                    y: biguint_to_32_bytes(&neg_y),
                });
            }
        }
    }
    None
}

/// Verify Grumpkin map-to-curve witness.
pub fn verify_grumpkin_witness(
    m: &BigUint,
    witness: &GrumpkinWitness,
    tweak_bound: u32,
) -> bool {
    if witness.tweak >= tweak_bound {
        return false;
    }
    let p = fr_modulus();
    let t = BigUint::from(tweak_bound);
    let k = BigUint::from(witness.tweak);
    let x = BigUint::from_bytes_be(&witness.x);
    let y = BigUint::from_bytes_be(&witness.y);
    let z = BigUint::from_bytes_be(&witness.z);

    // x == m * T + k
    let expected_x = (m * &t + &k) % &p;
    if x != expected_x {
        return false;
    }

    // y == z^2
    let z_sq = (&z * &z) % &p;
    if y != z_sq {
        return false;
    }

    // y^2 == x^3 - 17
    let y_sq = (&y * &y) % &p;
    let x_cubed = (&x * &x % &p) * &x % &p;
    let rhs = (&p + &x_cubed - BigUint::from(17u32)) % &p;
    y_sq == rhs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grumpkin_map_to_curve() {
        let m = BigUint::from(7u32);
        let witness = map_to_curve_grumpkin(&m, DEFAULT_TWEAK_BOUND).unwrap();
        assert!(verify_grumpkin_witness(&m, &witness, DEFAULT_TWEAK_BOUND));
    }

    #[test]
    fn test_grumpkin_matches_reference() {
        // Values from the reference repo test
        let m = BigUint::from(7u32);
        let witness = map_to_curve_grumpkin(&m, DEFAULT_TWEAK_BOUND).unwrap();
        assert_eq!(
            BigUint::from_bytes_be(&witness.x),
            BigUint::from(1792u32) // 7 * 256 + 0
        );
    }

    #[test]
    fn test_grumpkin_hash_and_map() {
        let (m, _) = hash_to_field_grumpkin(b"hello");
        let witness = map_to_curve_grumpkin(&m, DEFAULT_TWEAK_BOUND).unwrap();
        assert!(verify_grumpkin_witness(&m, &witness, DEFAULT_TWEAK_BOUND));
    }
}
