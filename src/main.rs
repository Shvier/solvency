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
use solvency::common::calculate_hash;
use solvency::verifier::Verifier;
use solvency::verkle_tree::tree::VerkleNode;

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

    let rng = &mut test_rng();

    let l1 = vec![80, 1, 20, 2, 50, 3, 10];
    let l2 = vec![60, 4, 10, 5, 30, 6, 10, 7, 10];
    let l3 = vec![100, 8, 30, 9, 70];
    let group1 = VerkleNode::from(rng, l1, None, MAX_BITS).expect("");
    let group2 = VerkleNode::from(rng, l2, None, MAX_BITS).expect("");
    let group3 = VerkleNode::from(rng, l3, None, MAX_BITS).expect("");

    let groups = [[group1.clone()], [group2]].concat();
    let intermediate = VerkleNode::from(rng, [].to_vec(), Some(groups), MAX_BITS).expect("");
    let root = VerkleNode::from(rng, [].to_vec(), Some([[intermediate.clone()], [group3]].concat()), MAX_BITS).expect("");
    assert_eq!(root.value, 240);

    let path = VerkleNode::generate_auth_path(&root, &[].to_vec());
    Verifier::verify(&path, 1, 20, &root);
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
