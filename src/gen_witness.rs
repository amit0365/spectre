//! Generates Prover.toml for the Noir map-to-curve circuit.
//!
//! Takes an input string, computes the map-to-curve witness,
//! and outputs the 8×32-bit LE chunk representation for each field element.

use k256::elliptic_curve::{
    point::AffineCoordinates,
    sec1::ToEncodedPoint,
};
use oprf_nullifier::hash_to_curve::{hash_to_field, map_to_curve_construct, DEFAULT_TWEAK_BOUND};

/// Convert a 32-byte big-endian field element to 8 little-endian 32-bit chunks.
fn fe_bytes_to_chunks(be_bytes: &[u8; 32]) -> [u32; 8] {
    let mut chunks = [0u32; 8];
    // The chunks are in little-endian order: chunk[0] is the least significant 32 bits.
    // Each chunk is a 4-byte little-endian value from the corresponding position.
    // BE bytes: [b0, b1, ..., b31] where b0 is most significant.
    // LE bytes would be [b31, b30, ..., b0].
    // Chunk 0 = LE bytes [0..4] = [b31, b30, b29, b28]
    for i in 0..8 {
        let base = 31 - (i * 4 + 3); // start of 4-byte group in BE
        chunks[i] = (be_bytes[base] as u32) << 24
            | (be_bytes[base + 1] as u32) << 16
            | (be_bytes[base + 2] as u32) << 8
            | (be_bytes[base + 3] as u32);
    }
    chunks
}

fn format_field_element(name: &str, chunks: &[u32; 8]) -> String {
    let items: Vec<String> = chunks.iter().map(|c| format!("    \"0x{:08x}\"", c)).collect();
    format!(
        "[{name}]\nitems = [\n{}\n]",
        items.join(",\n")
    )
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_else(|| "hello".to_string());
    eprintln!("Input: {:?}", input);

    // 1. Hash to field: m = SHA-256(input) mod p
    let (m, m_bytes) = hash_to_field(input.as_bytes());
    eprintln!("m = 0x{}", hex::encode(&m_bytes));

    // 2. Map to curve: find (point, witness)
    let (point, witness) = map_to_curve_construct(&m, DEFAULT_TWEAK_BOUND)
        .expect("map_to_curve should succeed");

    let point_affine = point;
    let x_bytes: [u8; 32] = point_affine.x().as_slice().try_into().unwrap();
    let y_bytes: [u8; 32] = point_affine
        .to_encoded_point(false)
        .y()
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();

    eprintln!("x = 0x{}", hex::encode(&x_bytes));
    eprintln!("y = 0x{}", hex::encode(&y_bytes));
    eprintln!("tweak k = {}", witness.tweak);
    eprintln!("z = 0x{}", hex::encode(&witness.z));

    // 3. Convert to 8×32-bit LE chunks
    let m_chunks = fe_bytes_to_chunks(&m_bytes);
    let x_chunks = fe_bytes_to_chunks(&x_bytes);
    let y_chunks = fe_bytes_to_chunks(&y_bytes);
    let z_chunks = fe_bytes_to_chunks(&witness.z);

    // nonce = tweak k as a FieldElement256 (just chunk[0] = k, rest = 0)
    let mut nonce_chunks = [0u32; 8];
    nonce_chunks[0] = witness.tweak;

    // 4. Output Prover.toml
    println!("{}", format_field_element("m", &m_chunks));
    println!();
    println!("{}", format_field_element("x", &x_chunks));
    println!();
    println!("{}", format_field_element("y", &y_chunks));
    println!();
    println!("{}", format_field_element("z", &z_chunks));
    println!();
    println!("{}", format_field_element("nonce", &nonce_chunks));
}
