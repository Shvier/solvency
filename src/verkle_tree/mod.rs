use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher, self};
use std::process::id;
use std::vec;

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

impl VerkleNode {
    pub fn from<R: Rng>(
        rng: &mut R,
        liabilities: Vec<u64>,
        children: Option<Vec<VerkleNode>>,
        max_bits: usize, 
    ) -> Result<Self, Error> {
        let children = match children {
            None => { Vec::<VerkleNode>::new() }
            Some(children) => { children.clone() }
        };
        let mut vectors = match liabilities.len() {
            0 => { [0].to_vec() }
            _ => { liabilities.clone() }
        };
        let mut total = vectors[0];
        match children.len() {
            0 => {}
            _ => {
                for node in children.clone() {
                    match node.kind {
                        NodeKind::Balance => {
                            vectors.push(node.value);
                            total += node.value;
                        }
                        NodeKind::Poly(_, com_p, _) => {
                            let hash_com_p = calculate_hash(&com_p);
                            vectors.push(hash_com_p);
                            vectors.push(node.value);
                            total += node.value;
                        }
                        NodeKind::Id(id) => {
                                vectors.push(id);
                        }
                    }
                }
            }
        }
        vectors[0] = total;

        let prover = Prover::setup(&vectors, max_bits).unwrap();
        let p = prover.p.clone();
        let i = prover.i.clone();
        let com_p = prover.commit(&p, rng).expect("");

        let nodes = generate_nodes_from(liabilities.clone(), Some(children.clone()));
        Ok(Self { 
            idx: 0,
            value: total,
            kind: NodeKind::Poly(p, com_p, i),
            children: Some(nodes),
         })
    }
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

fn generate_nodes_from(liabilities: Vec<u64>, children: Option<Vec<VerkleNode>>) -> Vec<VerkleNode> {
    let balances: Vec<VerkleNode> = liabilities.iter()
        .enumerate()
        .filter(|&(idx, _)| idx % 2 == 1) // odd positions store liability
        .map(|(idx, l)| { VerkleNode { 
            idx: idx,
            value: *l, 
            kind: NodeKind::Balance, 
            children: None 
        } })
        .collect();
    let ids: Vec<VerkleNode> = liabilities.iter()
        .enumerate()
        .filter(|&(idx, _)| idx % 2 == 0) // even positions store id
        .map(|(idx, l)| { VerkleNode { 
            idx: idx,
            value: 0, 
            kind: NodeKind::Id(*l), 
            children: None 
        } })
        .collect();
    let mut nodes: Vec<VerkleNode> = [balances, ids].concat();
    match children {
        None => {}
        Some(children) => {
            let mut idx = nodes.len();
            for child in children {
                let mut node = child.clone();
                match child.kind {
                    NodeKind::Balance | NodeKind::Id(_) => {}
                    NodeKind::Poly(_, com_p, _) => {
                        // insert the node that contains the hash value of the commitment
                        let hash_value = calculate_hash(&com_p);
                        let node = VerkleNode {
                            idx: idx,
                            value: 0,
                            kind: NodeKind::Id(hash_value),
                            children: None,
                        };
                        nodes.push(node);
                        idx += 1;
                    }
                }
                node.idx = idx;
                nodes.push(node);
                idx += 1;
            }
        }
    }
    nodes
}

#[cfg(test)]
fn generate_verkle_node() -> VerkleNode {
    use ark_std::test_rng;

    const MAX_BITS: usize = 16;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    VerkleNode::from(rng, liabilities.clone(), None, MAX_BITS).expect("Group setup failed")
}

#[test]
fn test_verkle_node_from_terminal_nodes() {
    use ark_poly::Polynomial;
    use ark_std::test_rng;
    use ark_ff::{FftField, Field};

    const MAX_BITS: usize = 16;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    let root = VerkleNode::from(rng, liabilities.clone(), None, MAX_BITS).expect("Node setup failed");
    assert_eq!(root.value, 80);

    match root.kind {
        NodeKind::Balance | NodeKind::Id(_) => { assert!(false) }
        NodeKind::Poly(p, _, _) => {
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

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    let node_1 = generate_verkle_node();
    let node_2 = generate_verkle_node();
    let nodes = [node_1, node_2].to_vec();
    let root = VerkleNode::from(rng, [].to_vec(), Some(nodes.clone()), MAX_BITS).expect("Root setup failed");
    assert_eq!(root.value, 160);

    let root = VerkleNode::from(rng, liabilities.clone(), Some(nodes.clone()), MAX_BITS).expect("Root setup failed");
    assert_eq!(root.value, 240);

    match root.kind {
        NodeKind::Balance | NodeKind::Id(_) => { assert!(false) }
        NodeKind::Poly(p, _, _) => {
            let len = (liabilities.len() + nodes.len() * 2).checked_next_power_of_two().unwrap();
            let omega = F::get_root_of_unity(len as u64).unwrap();
            for idx in 1..liabilities.len() - 1 {
                let point = omega.pow(&[idx as u64]);
                let target = F::from(liabilities[idx]);
                let eval = p.evaluate(&point);
                assert_eq!(eval, target);
            }

            let mut j = 0;
            for idx in (liabilities.len()..liabilities.len() + nodes.len() * 2 - 1).step_by(2) {
                let node = &nodes[j];
                match &node.kind {
                    NodeKind::Balance | NodeKind::Id(_) => {}
                    NodeKind::Poly(_, com_p, _) => {
                        let hash_value_of_com_p = calculate_hash(&com_p);
                        let point_com = omega.pow(&[idx as u64]);
                        let eval_hash = p.evaluate(&point_com);
                        assert_eq!(F::from(hash_value_of_com_p), eval_hash);
                    }
                }
                let point_value = omega.pow(&[(idx + 1) as u64]);
                let eval_value = p.evaluate(&point_value);
                assert_eq!(F::from(node.value), eval_value);
                j += 1;
            }
        }
    }
}
