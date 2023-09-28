use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain, univariate::DensePolynomial};
use ark_bls12_381::{Fr as F, Config, Bls12_381};
use ark_std::{rand::Rng, UniformRand};
use ark_poly_commit::kzg10::{Commitment, Randomness};

use crate::error::Error;
use crate::prover::data_structures::Prover;

pub mod tree;
use tree::*;

type D = Radix2EvaluationDomain::<F>;

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

#[derive(Clone)]
pub struct VerkleGroup {
    pub root: VerkleNode,
    pub com_p: Commitment<Bls12<Config>>,
    pub rand_p: Randomness<F, UniPoly_381>,
    pub com_w: Commitment<Bls12<Config>>,
    pub rand_w: Randomness<F, UniPoly_381>,
    pub groups: Option<Vec<VerkleGroup>>,
}

impl VerkleGroup {
    /// initialize the bottom nodes
    pub fn from_terminal_nodes<R: Rng>(
        rng: &mut R,
        liabilities: Vec<u64>,
        max_bits: usize, 
        max_degree: usize
    ) -> Result<Self, Error> {
        let domain = D::new(liabilities.len()).expect("Unsupported domain length");

        let prover = Prover::setup(domain, &liabilities, max_bits).unwrap();
        let p = prover.p.clone();
        let (com_p, r_p) = prover.commit(&p, rng, max_degree).expect("Commitment to P failed");
        let epsilon = F::rand(rng);
        let w = prover.compute_w(epsilon);
        let number_of_w_coeffs: usize = w.coeffs.len();
        let (com_w, r_w) = prover.commit(&w, rng, number_of_w_coeffs).expect("Commitment to W failed");

        let nodes = generate_nodes_from(liabilities.clone(), None);

        let root = VerkleNode::new(0, liabilities[0], NodeKind::Poly(p), Some(nodes));
        Ok(Self { root: root, com_p: com_p, rand_p: r_p, com_w: com_w, rand_w: r_w, groups: None })
    }

    pub fn from_intermediate_nodes<R: Rng>(
        rng: &mut R,
        liabilities: Vec<u64>,
        groups: Vec<VerkleGroup>,
        max_bits: usize, 
        max_degree: usize,
    ) -> Result<Self, Error> {
        let mut vectors = match liabilities.len() {
            0 => { [0].to_vec() }
            _ => { liabilities.clone() }
        };
        let mut total = vectors[0];
        for group in &groups {
            let hash_value_com = calculate_hash(&group.com_p);
            vectors.push(hash_value_com);
            let liability = group.root.value;
            vectors.push(liability);
            total += liability;
        }
        vectors[0] = total;

        let domain = D::new(vectors.len()).expect("Unsupported domain length");

        let prover = Prover::setup(domain, &vectors, max_bits).unwrap();
        let r = prover.p.clone();
        let (com_r, r_r) = prover.commit(&r, rng, max_degree).expect("Commitment to R failed");
        let epsilon = F::rand(rng);
        let w = prover.compute_w(epsilon);
        let number_of_w_coeffs: usize = w.coeffs.len();
        let (com_w, r_w) = prover.commit(&w, rng, number_of_w_coeffs).expect("Commitment to W failed");

        let nodes = generate_nodes_from(liabilities.clone(), Some(groups.clone()));
        let root = VerkleNode::new(0, total, NodeKind::Poly(r), Some(nodes));
        Ok(Self { root: root, com_p: com_r, rand_p: r_r, com_w: com_w, rand_w: r_w, groups: Some(groups) })
    }
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

fn generate_nodes_from(liabilities: Vec<u64>, groups: Option<Vec<VerkleGroup>>) -> Vec<VerkleNode> {
    let mut nodes: Vec<VerkleNode> = liabilities.iter()
    .enumerate()
    .map(|(idx, l)| { VerkleNode { 
        id: idx,
        value: *l, 
        kind: NodeKind::Balance, 
        children: None 
    } })
    .collect();
    match groups {
        None => {}
        Some(groups) => {
            let mut idx = nodes.len();
            for group in groups {
                let mut node = group.root;
                node.id = idx;
                nodes.push(node);
                idx += 1;
            }
        }
    }
    nodes
}

#[cfg(test)]
fn generate_verkle_group() -> VerkleGroup {
    use ark_std::test_rng;

    const MAX_BITS: usize = 16;
    const MAX_DEGREE: usize = 64;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    VerkleGroup::from_terminal_nodes(rng, liabilities.clone(), MAX_BITS, MAX_DEGREE).expect("Group setup failed")
}

#[test]
fn test_verkle_group_terminal_nodes() {
    use ark_poly::Polynomial;
    use ark_std::test_rng;
    use ark_ff::{FftField, Field};

    const MAX_BITS: usize = 16;
    const MAX_DEGREE: usize = 64;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    let group = VerkleGroup::from_terminal_nodes(rng, liabilities.clone(), MAX_BITS, MAX_DEGREE).expect("Group setup failed");
    assert_eq!(group.root.value, 80);

    match group.root.kind {
        NodeKind::Balance => { assert!(false) }
        NodeKind::Poly(p) => {
            let len = liabilities.len().checked_next_power_of_two().unwrap();
            let omega = F::get_root_of_unity(len as u64).unwrap();
            for idx in 0..len - 1 {
                let point = omega.pow(&[idx as u64]);
                let target = F::from(liabilities[idx]);
                let eval = p.evaluate(&point);
                assert_eq!(eval, target);
            }
        }
    };
}

#[test]
fn test_verkle_group_intermediate_nodes() {
    use ark_poly::Polynomial;
    use ark_std::test_rng;
    use ark_ff::{FftField, Field};

    const MAX_BITS: usize = 16;
    const MAX_DEGREE: usize = 64;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    let group_1 = generate_verkle_group();
    let group_2 = generate_verkle_group();
    let groups = [group_1, group_2].to_vec();
    let verkle_root = VerkleGroup::from_intermediate_nodes(rng, [].to_vec(), groups.clone(), MAX_BITS, MAX_DEGREE).expect("Root setup failed");
    assert_eq!(verkle_root.root.value, 160);

    let verkle_root = VerkleGroup::from_intermediate_nodes(rng, liabilities.clone(), groups.clone(), MAX_BITS, MAX_DEGREE).expect("Root setup failed");
    assert_eq!(verkle_root.root.value, 240);

    match verkle_root.root.kind {
        NodeKind::Balance => { assert!(false) }
        NodeKind::Poly(r) => {
            let len = (liabilities.len() + groups.len() * 2).checked_next_power_of_two().unwrap();
            let omega = F::get_root_of_unity(len as u64).unwrap();
            for idx in 1..liabilities.len() - 1 {
                let point = omega.pow(&[idx as u64]);
                let target = F::from(liabilities[idx]);
                let eval = r.evaluate(&point);
                assert_eq!(eval, target);
            }

            let mut j = 0;
            for idx in (liabilities.len()..liabilities.len() + groups.len() * 2 - 1).step_by(2) {
                let group = &groups[j];
                let point_com = omega.pow(&[idx as u64]);
                let point_value = omega.pow(&[(idx + 1) as u64]);
                let com_p = group.com_p;
                let hash_value_of_com_p = calculate_hash(&com_p);
                let eval_hash = r.evaluate(&point_com);
                let eval_value = r.evaluate(&point_value);
                assert_eq!(F::from(hash_value_of_com_p), eval_hash);
                assert_eq!(F::from(group.root.value), eval_value);
                j += 1;
            }
        }
    }
}
