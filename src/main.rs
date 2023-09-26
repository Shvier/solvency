use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use ark_ec::pairing::Pairing;
use ark_bls12_381::Bls12_381;
use ark_poly::Radix2EvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use ark_std::test_rng;
use ark_std::rand::Rng;
use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

type D = Radix2EvaluationDomain::<F>;

struct ConstraintsVerification {
    quotient_p: DensePolynomial<<Bls12_381 as Pairing>::ScalarField>,
    quotient_w: DensePolynomial<<Bls12_381 as Pairing>::ScalarField>,
}

impl ConstraintSynthesizer<F> for ConstraintsVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        Ok(())
    }
}

fn main() {
    const MAX_BITS: usize = 16;
    const MAX_DEGREE: usize = 64;
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

fn generate_liabilities() -> Vec<u64> {
    let rng = &mut test_rng();

    let usernames: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    let liabilities: Vec<u64> = usernames.iter()
        .map(|_| { rng.gen_range(0..2_u64.pow(15)) })
        .collect();
    println!("{:?}", liabilities);

    let total: u64 = liabilities.iter().copied().sum();
    println!("total: {}", total);

    let mut vectors = Vec::<u64>::new();

    for (username, liability) in usernames.into_iter().zip(liabilities.into_iter()).rev() {
        let id = calculate_hash(&username);
        vectors.push(liability);
        vectors.push(id);
    }

    vectors.push(total);
    vectors.reverse();
    vectors
}
