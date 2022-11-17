use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Projective, G2Prepared, G2Projective, Scalar,
};
use ff::Field;
use group::{Curve, Group};
use rand::RngCore;
use sha2::{Digest, Sha512};

/// G1 hash domain as defined by IETF:
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-J.9.1
const G1_HASH_DOMAIN: &[u8] = b"BLS-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// The scheme public parameters.
pub struct Parameters {
    pub g2: G2Projective,
}

impl Parameters {
    /// Create new parameters.
    pub fn new() -> Self {
        Self {
            g2: G2Projective::generator(),
        }
    }

    /// Hash a byte message into an element of G1.
    pub fn hash_to_g1<M: AsRef<[u8]>>(msg: M) -> G1Projective {
        <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            msg,
            G1_HASH_DOMAIN,
        )
    }

    /// Hash a byte message into a scalar.
    pub fn hash_to_scalar<M: AsRef<[u8]>>(msg: M) -> Scalar {
        let seed = Sha512::digest(msg.as_ref());
        Scalar::from_raw([
            u64::from_le_bytes(seed.as_slice()[..8].try_into().unwrap()),
            u64::from_le_bytes(seed.as_slice()[8..16].try_into().unwrap()),
            u64::from_le_bytes(seed.as_slice()[16..24].try_into().unwrap()),
            u64::from_le_bytes(seed.as_slice()[24..32].try_into().unwrap()),
        ])
    }

    /// Check whether `e(P, Q) * e(-R, S) == id`.
    pub fn check_pairing(
        p: &G1Projective,
        q: &G2Projective,
        r: &G1Projective,
        s: &G2Projective,
    ) -> bool {
        let p = &p.to_affine();
        let q = &G2Prepared::from(q.to_affine());
        let r = &r.to_affine();
        let s = &G2Prepared::from(s.to_affine());

        bls12_381::multi_miller_loop(&[(p, q), (&(-r), s)])
            .final_exponentiation()
            .is_identity()
            .into()
    }
}

/// A BLS secret key.
pub struct SecretKey(pub Scalar);

impl SecretKey {
    /// Generate a new (random) secret key.
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }
}

/// The BLS public key.
#[derive(Clone)]
pub struct PublicKey(pub G2Projective);

impl PublicKey {
    /// The length of a serialized public key.
    pub const SERIALIZED_LENGTH: usize = 192;

    /// Generate a new public key from the public parameters and a secret key.
    pub fn new(parameters: &Parameters, secret: &SecretKey) -> Self {
        Self(parameters.g2 * secret.0)
    }

    /// Serialize the public key into bytes.
    pub fn serialize(&self) -> [u8; Self::SERIALIZED_LENGTH] {
        self.0.to_affine().to_uncompressed()
    }
}

/// The BLS signature representation.
pub struct Signature(pub G1Projective);

impl Signature {
    /// Sign a byte message.
    pub fn new<M: AsRef<[u8]>>(msg: M, sk: &SecretKey) -> Self {
        Self(Parameters::hash_to_g1(msg) * sk.0)
    }

    /// Verify a signature.
    pub fn verify<M: AsRef<[u8]>>(&self, msg: M, parameters: &Parameters, pk: &PublicKey) -> bool {
        Parameters::check_pairing(&self.0, &parameters.g2, &Parameters::hash_to_g1(msg), &pk.0)
    }
}
