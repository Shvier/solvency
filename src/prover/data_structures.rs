use ark_bls12_381::{Fr as F, Bls12_381};
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain};

use crate::verkle_tree::tree::{ProofIdNode, ProofValueNode};

pub struct Prover {
    pub max_bits: usize,
    pub p: DensePolynomial<F>,
    pub i: DensePolynomial<F>,
    pub liabilities: Vec<u64>,
    pub aux_vec: Vec<u64>,
    pub domain: Radix2EvaluationDomain<F>,
}

pub struct SolProof {
    pub root: ProofValueNode,
    pub children: Vec<(ProofIdNode, ProofValueNode)>,
}

#[cfg(test)]
pub fn generate_prover() -> Prover {
    const MAX_BITS: usize = 16;

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    Prover::setup(&liabilities, MAX_BITS).unwrap()
}
