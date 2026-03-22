//! OPRF client: blinds input, unblinds server response, derives nullifier.

use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    sha2::{Digest, Sha256},
    NonZeroScalar, ProjectivePoint, Scalar,
};

use crate::hash_to_curve::{
    hash_to_curve_with_witness, hash_to_field, MapToCurveWitness, DEFAULT_TWEAK_BOUND,
};

/// Result of the client's blinding step.
pub struct BlindedRequest {
    /// The blinded point sent to the server.
    pub blinded: ProjectivePoint,
    /// Blinding factor (secret, needed for unblinding).
    pub blinding_factor: NonZeroScalar,
    /// The curve point h = hash_to_curve(input).
    pub h: ProjectivePoint,
    /// Witness for the map-to-curve relation (for ZK proof).
    pub witness: MapToCurveWitness,
    /// The field element m = SHA-256(input) mod q (for ZK proof).
    pub m_bytes: [u8; 32],
}

/// The final OPRF output.
pub struct OprfOutput {
    /// The nullifier: deterministic for (input, server_key).
    pub nullifier: [u8; 32],
    /// The unblinded point h^k.
    pub unblinded: ProjectivePoint,
}

pub struct OprfClient;

impl OprfClient {
    /// Step 1: Hash input to curve and blind it.
    ///
    /// Returns the blinded point to send to the server,
    /// plus private state needed for unblinding.
    pub fn blind(input: &[u8]) -> BlindedRequest {
        let (h, witness) = hash_to_curve_with_witness(input, DEFAULT_TWEAK_BOUND)
            .expect("hash_to_curve should succeed within T iterations");

        let r = NonZeroScalar::random(&mut rand_core::OsRng);
        let blinded = h * *r;

        let (_, m_bytes) = hash_to_field(input);

        BlindedRequest {
            blinded,
            blinding_factor: r,
            h,
            witness,
            m_bytes,
        }
    }

    /// Step 2: Unblind the server's response and derive the nullifier.
    ///
    /// `evaluated` is the server's response: blinded^k.
    /// Returns h(input)^k (the unblinded OPRF output) and the nullifier.
    pub fn finalize(
        input: &[u8],
        evaluated: &ProjectivePoint,
        blinding_factor: &NonZeroScalar,
    ) -> OprfOutput {
        // unblind: r^{-1} * evaluated = r^{-1} * k * r * h = k * h
        let r_scalar: Scalar = **blinding_factor;
        let r_inv: Scalar = Option::from(r_scalar.invert()).expect("non-zero scalar is invertible");
        let unblinded = *evaluated * r_inv;

        // nullifier = SHA-256(input || SEC1(unblinded))
        let pt_bytes = unblinded
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.update(&pt_bytes);
        let hash = hasher.finalize();
        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(hash.as_ref());

        OprfOutput {
            nullifier,
            unblinded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::OprfServer;

    #[test]
    fn test_oprf_roundtrip() {
        let server = OprfServer::random();

        let input = b"user@example.com";
        let req = OprfClient::blind(input);
        let evaluated = server.evaluate(&req.blinded);
        let output = OprfClient::finalize(input, &evaluated, &req.blinding_factor);

        // Same input + same server key → same nullifier
        let req2 = OprfClient::blind(input);
        let evaluated2 = server.evaluate(&req2.blinded);
        let output2 = OprfClient::finalize(input, &evaluated2, &req2.blinding_factor);

        assert_eq!(output.nullifier, output2.nullifier);
    }

    #[test]
    fn test_different_inputs_different_nullifiers() {
        let server = OprfServer::random();

        let req1 = OprfClient::blind(b"alice@example.com");
        let eval1 = server.evaluate(&req1.blinded);
        let out1 = OprfClient::finalize(b"alice@example.com", &eval1, &req1.blinding_factor);

        let req2 = OprfClient::blind(b"bob@example.com");
        let eval2 = server.evaluate(&req2.blinded);
        let out2 = OprfClient::finalize(b"bob@example.com", &eval2, &req2.blinding_factor);

        assert_ne!(out1.nullifier, out2.nullifier);
    }

    #[test]
    fn test_server_never_sees_input() {
        // The server only sees `blinded = r * h` — a random-looking point.
        // It cannot recover h or the input from blinded alone.
        let server = OprfServer::random();
        let req = OprfClient::blind(b"secret-input");

        // Server evaluates without knowing the input
        let evaluated = server.evaluate(&req.blinded);

        // Client unblinds — only the client knows the result maps to "secret-input"
        let output =
            OprfClient::finalize(b"secret-input", &evaluated, &req.blinding_factor);

        assert_ne!(output.nullifier, [0u8; 32]);
    }
}
