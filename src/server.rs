//! OPRF server: holds secret key, evaluates blinded points.

use k256::{NonZeroScalar, ProjectivePoint};

pub struct OprfServer {
    key: NonZeroScalar,
}

impl OprfServer {
    pub fn new(key: NonZeroScalar) -> Self {
        Self { key }
    }

    pub fn random() -> Self {
        Self {
            key: NonZeroScalar::random(&mut rand_core::OsRng),
        }
    }

    /// Evaluate: returns blinded^k
    pub fn evaluate(&self, blinded: &ProjectivePoint) -> ProjectivePoint {
        *blinded * *self.key
    }

    /// Public key = k * G (for verification / key registry)
    pub fn public_key(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * *self.key
    }
}
