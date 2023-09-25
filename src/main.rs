use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use ark_ec::{VariableBaseMSM, CurveGroup};
use ark_ff::{PrimeField, FftField, Field, Zero};
use ark_poly_commit::kzg10::{KZG10, Powers, VerifierKey, Proof};
use ark_bls12_381::Bls12_381;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain, GeneralEvaluationDomain};
use ark_poly::univariate::DensePolynomial;
use ark_ec::pairing::Pairing;
use ark_std::{test_rng, start_timer, end_timer};
use ark_std::rand::Rng;
use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use solvency::prover;

use prover::data_structures::Prover;

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

    // KZG trusted setup
    let rng = &mut test_rng();
    

    let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(MAX_DEGREE, false, rng).expect("Setup failed");

    // Convert liabilities into vectors and interpolate P
    let liabilities = generate_liabilities();
    // let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let domain = D::new(liabilities.len()).expect("Unsupported domain length");

    let prover = Prover::setup(domain, pcs, liabilities, MAX_BITS, MAX_DEGREE);
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
