use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use ark_bls12_381::{Fr as F, Config, Bls12_381};
use ark_poly_commit::kzg10::{Commitment, Randomness};

#[derive(Clone)]
pub enum NodeKind {
    Poly(DensePolynomial<F>, (Commitment<Bls12<Config>>, Randomness<F, DensePolynomial<<Bls12_381 as Pairing>::ScalarField>>), DensePolynomial<F>),
    Balance,
    Id(u64), // user id or hash of commitment
}

#[derive(Clone)]
pub struct VerkleNode {
    pub idx: usize, // idx in the vector commitment
    pub value: u64, // liability
    pub kind: NodeKind,
    pub children: Option<Vec<VerkleNode>>,
}

impl VerkleNode {
    pub fn new(
        idx: usize,
        value: u64, 
        kind: NodeKind, 
        children: Option<Vec<VerkleNode>>
    ) -> VerkleNode {
        VerkleNode { 
            idx: idx, 
            value: value, 
            kind: kind, 
            children: children 
        }
    }
}
