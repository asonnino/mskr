use bls::{Parameters, PublicKey, SecretKey, Signature};
use bls12_381::{G1Projective, G2Projective, Scalar};

pub mod bls;

pub trait MskrSecretKey {
    /// Randomize the secret key using the input list of public keys.
    fn randomize(&self, pk: &PublicKey, pks: &[PublicKey]) -> SecretKey;
}

pub trait Mskr {
    /// Generate the random seed from the public keys.
    fn seed(&self, pk: &PublicKey, pks: &[PublicKey]) -> Scalar {
        let mut seed = Vec::with_capacity(PublicKey::SERIALIZED_LENGTH * (pks.len() + 1));
        seed.extend_from_slice(&pk.serialize());
        for pk in pks {
            seed.extend_from_slice(&pk.serialize());
        }
        Parameters::hash_to_scalar(seed)
    }

    /// Randomize the public key using the input list of public keys.
    fn randomize(&self, pk: &PublicKey, pks: &[PublicKey]) -> Self;

    /// Aggregate multiple signatures.
    fn aggregate(sigs: &[Self]) -> Self
    where
        Self: Sized;
}

impl MskrSecretKey for SecretKey {
    fn randomize(&self, pk: &PublicKey, pks: &[PublicKey]) -> Self {
        let mut seed = Vec::with_capacity(PublicKey::SERIALIZED_LENGTH * (pks.len() + 1));
        seed.extend_from_slice(&pk.serialize());
        for pk in pks {
            seed.extend_from_slice(&pk.serialize());
        }
        Self(self.0 * Parameters::hash_to_scalar(seed))
    }
}

impl Mskr for PublicKey {
    fn randomize(&self, _pk: &Self, pks: &[Self]) -> Self {
        Self(self.0 * self.seed(self, pks))
    }

    fn aggregate(pks: &[Self]) -> Self {
        Self(pks.iter().map(|x| x.0).sum::<G2Projective>())
    }
}

impl Mskr for Signature {
    /// Aggregate multiple signatures.
    fn aggregate(sigs: &[Self]) -> Self {
        Self(sigs.iter().map(|x| x.0).sum::<G1Projective>())
    }

    fn randomize(&self, pk: &PublicKey, pks: &[PublicKey]) -> Self {
        Self(self.0 * self.seed(pk, pks))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        bls::{Parameters, PublicKey, SecretKey, Signature},
        Mskr, MskrSecretKey,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn verify_plain() {
        let mut rng = StdRng::from_seed([0; 32]);
        let parameters = Parameters::new();

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::new(&parameters, &sk);

        let msg: &[u8] = b"Hello, world!";
        let signature = Signature::new(msg, &sk);

        assert!(signature.verify(msg, &parameters, &pk))
    }

    #[test]
    fn verify_randomize_key() {
        let mut rng = StdRng::from_seed([0; 32]);
        let parameters = Parameters::new();

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::new(&parameters, &sk);

        let pks = (0..4)
            .map(|_| {
                let sk = SecretKey::new(&mut rng);
                PublicKey::new(&parameters, &sk)
            })
            .collect::<Vec<_>>();

        let msg: &[u8] = b"Hello, world!";
        let sig = Signature::new(msg, &sk.randomize(&pk, &pks));

        assert!(sig.verify(msg, &parameters, &pk.randomize(&pk, &pks)))
    }

    #[test]
    fn verify_randomize_signature() {
        let mut rng = StdRng::from_seed([0; 32]);
        let parameters = Parameters::new();

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::new(&parameters, &sk);

        let pks = (0..4)
            .map(|_| {
                let sk = SecretKey::new(&mut rng);
                PublicKey::new(&parameters, &sk)
            })
            .collect::<Vec<_>>();

        let msg: &[u8] = b"Hello, world!";
        let sig = Signature::new(msg, &sk).randomize(&pk, &pks);

        assert!(sig.verify(msg, &parameters, &pk.randomize(&pk, &pks)))
    }

    #[test]
    fn verify_aggregate_all() {
        let mut rng = StdRng::from_seed([0; 32]);
        let parameters = Parameters::new();

        let (sks, pks): (Vec<_>, Vec<_>) = (0..4)
            .map(|_| {
                let sk = SecretKey::new(&mut rng);
                let pk = PublicKey::new(&parameters, &sk);
                (sk, pk)
            })
            .unzip();

        let msg: &[u8] = b"Hello, world!";
        let sigs = sks
            .iter()
            .zip(pks.iter())
            .map(|(sk, pk)| Signature::new(msg, &sk.randomize(pk, &pks)))
            .collect::<Vec<_>>();

        let randomized_pks = pks
            .iter()
            .map(|pk| pk.randomize(&pk, &pks))
            .collect::<Vec<_>>();
        let aggregate_pk = PublicKey::aggregate(&randomized_pks);
        let aggregate_sig = Signature::aggregate(&sigs);

        assert!(aggregate_sig.verify(msg, &parameters, &aggregate_pk))
    }

    #[test]
    fn verify_aggregate_subset() {
        let mut rng = StdRng::from_seed([0; 32]);
        let parameters = Parameters::new();

        let (sks, pks): (Vec<_>, Vec<_>) = (0..4)
            .map(|_| {
                let sk = SecretKey::new(&mut rng);
                let pk = PublicKey::new(&parameters, &sk);
                (sk, pk)
            })
            .unzip();

        let msg: &[u8] = b"Hello, world!";
        let sigs = sks
            .iter()
            .zip(pks.iter())
            .skip(1)
            .map(|(sk, pk)| Signature::new(msg, &sk.randomize(pk, &pks)))
            .collect::<Vec<_>>();

        let randomized_pks = pks
            .iter()
            .skip(1)
            .map(|pk| pk.randomize(&pk, &pks))
            .collect::<Vec<_>>();
        let aggregate_pk = PublicKey::aggregate(&randomized_pks);
        let aggregate_sig = Signature::aggregate(&sigs);

        assert!(aggregate_sig.verify(msg, &parameters, &aggregate_pk))
    }
}
