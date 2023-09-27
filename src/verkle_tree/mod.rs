use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain, univariate::DensePolynomial};
use ark_bls12_381::{Fr as F, Config, Bls12_381};
use ark_std::{rand::Rng, UniformRand};
use ark_poly_commit::kzg10::{Commitment, Randomness, UniversalParams};

use crate::error::Error;
use crate::prover::data_structures::Prover;

pub mod tree;
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
        pcs: UniversalParams<Bls12_381>,
        liabilities: Vec<u64>,
        max_bits: usize, 
        max_degree: usize
    ) -> Result<Self, Error> {
        let domain = D::new(liabilities.len()).expect("Unsupported domain length");

        let prover = Prover::setup(domain, pcs, &liabilities, max_bits, max_degree).unwrap();
        let p = prover.p.clone();
        let (com_p, r_p) = prover.commit(&p, rng, max_degree).expect("Commitment to p failed");
        let epsilon = F::rand(rng);
        let w = prover.compute_w(epsilon);
        let number_of_w_coeffs: usize = w.coeffs.len();
        let (com_w, r_w) = prover.commit(&w, rng, number_of_w_coeffs).expect("Commitment to w failed");

        let nodes = generate_nodes_from(&liabilities);

        let root = VerkleNode::new(liabilities[0], NodeKind::Poly(p), Some(nodes));
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
        pcs: UniversalParams<Bls12_381>,
        liabilities: Vec<u64>,
        groups: Vec<VerkleGroup>,
        max_bits: usize, 
        max_degree: usize,
    ) -> Result<Self, Error> {
        let mut vectors = liabilities.clone();
        let mut total = liabilities[0];
        for group in &groups {
            let hash_value_com = calculate_hash(&group.com_p);
            vectors.push(hash_value_com);
            let liability = group.root.value;
            vectors.push(liability);
            total += liability;
        }
        vectors[0] = total;

        let domain = D::new(vectors.len()).expect("Unsupported domain length");

        let prover = Prover::setup(domain, pcs, &vectors, max_bits, max_degree).unwrap();
        let r = prover.p.clone();
        let (com_r, r_r) = prover.commit(&r, rng, max_degree).expect("Commitment to r failed");
        let epsilon = F::rand(rng);
        let w = prover.compute_w(epsilon);
        let number_of_w_coeffs: usize = w.coeffs.len();
        let (com_w, r_w) = prover.commit(&w, rng, number_of_w_coeffs).expect("Commitment to w failed");

        let nodes = generate_nodes_from(&vectors);
        let root = VerkleNode::new(total, NodeKind::Poly(r), Some(nodes));
        Ok(Self { root: root, groups: groups, com_r: com_r, rand_r: r_r, com_w: com_w, rand_w: r_w })
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

#[test]
fn test_verkle_group() {
    use ark_poly_commit::kzg10::KZG10;
    use ark_poly::Polynomial;
    use ark_std::test_rng;
    use ark_ff::{FftField, Field};

    const MAX_BITS: usize = 16;
    const MAX_DEGREE: usize = 64;

    let rng = &mut test_rng();
    let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(MAX_DEGREE, false, rng).expect("Setup failed");

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    let group = VerkleGroup::setup(rng, pcs, liabilities.clone(), MAX_BITS, MAX_DEGREE).expect("Group setup failed");
    assert_eq!(group.root.value, 80);

    match group.root.kind {
        NodeKind::Balance => {}
        NodeKind::Poly(p) => {
            let len = liabilities.len().checked_next_power_of_two().unwrap();
            let omega = F::get_root_of_unity(len as u64).expect("");
            for idx in 0..len - 1 {
                let point = omega.pow(&[idx as u64]);
                let target = F::from(liabilities[idx]);
                let eval = p.evaluate(&point);
                assert_eq!(eval, target);
            }
        }
    };
}
