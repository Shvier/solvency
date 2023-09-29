use std::fmt;

use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use ark_bls12_381::{Fr as F, Config, Bls12_381};
use ark_poly_commit::kzg10::{Commitment, Randomness};

#[derive(Clone, PartialEq, Debug)]
pub enum NodeKind {
    Poly(
        DensePolynomial<F>, 
        (Commitment<Bls12<Config>>, Randomness<F, DensePolynomial<<Bls12_381 as Pairing>::ScalarField>>), 
        DensePolynomial<F>
    ),
    Balance,
    UserId,
    ComHash
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
       match self {
            NodeKind::Poly(_, _, _) => write!(f, "Poly"),
            NodeKind::Balance => write!(f, "Balance"),
            NodeKind::UserId => write!(f, "UserId"),
            NodeKind::ComHash => write!(f, "ComHash"),
       }
    }
}

#[derive(Clone, Debug)]
pub struct VerkleNode {
    pub id: u64, // user id or hash of commitment
    pub idx: usize, // idx in the vector commitment
    pub value: u64, // liability
    pub kind: NodeKind,
    pub children: Option<Vec<VerkleNode>>,
}

impl VerkleNode {
    pub fn new(
        id: u64,
        idx: usize,
        value: u64, 
        kind: NodeKind, 
        children: Option<Vec<VerkleNode>>
    ) -> VerkleNode {
        VerkleNode { 
            id: id,
            idx: idx, 
            value: value, 
            kind: kind, 
            children: children 
        }
    }
}
