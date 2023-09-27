use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain, univariate::DensePolynomial};
use ark_bls12_381::{Fr as F, Config, Bls12_381};
use ark_std::{rand::Rng, UniformRand, borrow::Cow};

use crate::error::Error;
use crate::prover::data_structures::Prover;

pub mod tree;
use ark_poly_commit::kzg10::{KZG10, Powers, Commitment, Randomness};
use tree::*;

type D = Radix2EvaluationDomain::<F>;

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

pub struct VerkleGroup {
    pub root: VerkleNode,
    pub com_p: Commitment<Bls12<Config>>,
    pub rand_p: Randomness<F, UniPoly_381>,
    pub com_w: Commitment<Bls12<Config>>,
    pub rand_w: Randomness<F, UniPoly_381>,
}

impl VerkleGroup {
    /// initialize the bottom nodes
    pub fn setup<R: Rng>(
        rng: &mut R,
        liabilities: Vec<u64>,
        max_bits: usize, 
        max_degree: usize
    ) -> Result<Self, Error> {
        let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).expect("Setup failed");
        let vectors = liabilities.clone();
        let domain = D::new(vectors.len()).expect("Unsupported domain length");

        let prover = Prover::setup(domain, pcs, &vectors, max_bits, max_degree).unwrap();
        let p = prover.p.clone();
        let (com_p, r_p) = prover.commit(&p).expect("Commitment to p failed");
        let epsilon = F::rand(rng);
        let w = prover.compute_w(epsilon);
        let (com_w, r_w) = prover.commit(&w).expect("Commitment to w failed");
        let hash_com_p = calculate_hash(&com_p);

        let non_leaf_nodes = generate_nodes_from(&vectors);
        let root = VerkleNode::new(hash_com_p, NodeKind::Poly(p), Some(non_leaf_nodes));
        Ok(Self { root: root, com_p: com_p, rand_p: r_p, com_w: com_w, rand_w: r_w })
    }
}

pub struct VerkleRoot {
    pub root: VerkleNode,
    pub groups: Vec<VerkleGroup>,
    pub com_r: Commitment<Bls12<Config>>,
    pub rand_r: Randomness<F, UniPoly_381>,
    pub com_w: Commitment<Bls12<Config>>,
    pub rand_w: Randomness<F, UniPoly_381>,
}

impl VerkleRoot {
    pub fn setup<R: Rng>(
        rng: &mut R,
        liabilities: Vec<u64>,
        groups: Vec<VerkleGroup>,
        max_bits: usize, 
        max_degree: usize,
    ) {

    }
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

fn generate_nodes_from(liabilities: &Vec<u64>) -> Vec<VerkleNode> {
    assert!(liabilities.len() >= 3);
    let nodes = liabilities.iter()
    .enumerate()
    .map(|(_, l)| { VerkleNode { 
        value: *l, 
        kind: NodeKind::Balance, 
        children: None 
    } })
    .collect();
    nodes
}
