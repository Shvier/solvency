use std::collections::HashMap;

use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain, univariate::DensePolynomial};
use ark_bls12_381::{Fr as F, Config, Bls12_381};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_std::test_rng;
use ark_std::{rand::Rng, UniformRand};
use ark_poly_commit::kzg10::{Commitment, Randomness, UniversalParams, KZG10, Proof};
use ark_ff::{FftField, Field};

use crate::common::calculate_hash;
use crate::error::Error;
use crate::prover::constraints::PolyCopyConstraints;
use crate::prover::data_structures::Prover;
use crate::utils::{substitute_x, compute_aux_vector};
use crate::verifier::Verifier;

pub mod tree;
use tree::*;

type D = Radix2EvaluationDomain::<F>;

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

impl VerkleNode {
    pub fn from(
        pcs: &UniversalParams<Bls12_381>,
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
                        NodeKind::Poly(poly_proof) => {
                            let hash_com_p = calculate_hash(&poly_proof.com_p);
                            vectors.push(hash_com_p);
                            vectors.push(node.value);
                            total += node.value;
                        }
                        _ => {
                                vectors.push(node.id);
                        }
                    }
                }
            }
        }
        vectors[0] = total;

        let prover = Prover::setup(&vectors, max_bits).unwrap();
        let p = prover.p.clone();
        let i = prover.i.clone();
        let w1 = prover.compute_w1();
        let w2 = prover.compute_w2();
        let w3 = prover.compute_w3();

        let (com_p, rand) = prover.commit(&p, pcs).expect("");
        let omega = F::get_root_of_unity((p.coeffs.len() as u64).checked_next_power_of_two().unwrap()).expect("");

        let hash_of_com_p = calculate_hash(&com_p);

        let mut proofs = Vec::<NodePolyProofPair>::new();
        let nodes = generate_nodes_from(total, liabilities.clone(), Some(children.clone()));

        for idx in 0..vectors.len() {
            let point = omega.pow(&[idx as u64]);
            let witness_p = Prover::compute_proof(&p, &pcs, point, rand.clone()).expect("");
            let node = &nodes[idx];
            match &node.kind {
                NodeKind::Poly(poly_proof) => {
                    let sub_p = &poly_proof.p;
                    let p_shifted = substitute_x::<F, D>(&p, 1, node.idx);
                    let z = &p_shifted - sub_p;
                    let (com_z, rand_z) = prover.commit(&z, pcs).expect("");
                    let witness_z = Prover::compute_proof(&z, &pcs, F::from(1), rand_z).expect("");
                    let proof_z = (com_z, witness_z);
                    let proof_pair = NodePolyProofPair {
                        witness_p,
                        proof_z: Some(proof_z),
                    };
                    proofs.push(proof_pair);
                }
                _ => {
                    let proof_pair = NodePolyProofPair {
                        witness_p,
                        proof_z: None,
                    };
                    proofs.push(proof_pair);
                }
            }
        }

        Ok(Self { 
            id: hash_of_com_p,
            idx: 0,
            value: total,
            kind: NodeKind::Poly(NodePolyProof { 
                p,
                com_p,
                i,
                w1,
                w2, 
                w3,
                proofs
            }),
            children: Some(nodes),
         })
    }

    pub fn generate_auth_path(root: &VerkleNode, prefix: &Vec<u64>) -> HashMap<u64, Vec<u64>> {
        let mut path = HashMap::<u64, Vec<u64>>::new();
        match root.kind {
            NodeKind::Poly(_) => {
                if let Some(children) = &root.children {
                    for idx in 0..children.len() {
                        let child = &children[idx];
                        match &child.kind {
                            NodeKind::UserId | NodeKind::ComHash => {}
                            NodeKind::Balance => {
                                let mut vec: Vec<u64> = match path.contains_key(&child.id) {
                                    true => {
                                        path.get(&child.id).unwrap().to_vec()
                                    }
                                    false => {
                                        Vec::<u64>::new()
                                    }
                                };
                                vec.extend(prefix);
                                vec.push(idx as u64);
                                path.insert(child.id, vec.to_vec());
                            }
                            NodeKind::Poly(_) => {
                                let idx_vec = [idx as u64].to_vec();
                                let mut new_prefix = prefix.clone();
                                new_prefix.extend(idx_vec);
                                let sub_path = VerkleNode::generate_auth_path(child, &new_prefix);
                                path.extend(sub_path.into_iter().map(|(k, v)| (k.clone(), v.clone())));
                            }
                        }
                    }
                }
                path
            }
            NodeKind::UserId => {
                let id = root.id;
                let mut vec: Vec<u64> = match path.contains_key(&id) {
                    true => {
                        path.get(&id).unwrap().to_vec()
                    }
                    false => {
                        Vec::<u64>::new()
                    }
                };
                vec.push(id);
                path.insert(id, vec.to_vec());
                path
            }
            _ => { 
                path
            }
        }
    }
}

fn generate_nodes_from(total: u64, liabilities: Vec<u64>, children: Option<Vec<VerkleNode>>) -> Vec<VerkleNode> {
    let mut nodes = Vec::<VerkleNode>::new();
    let total_node = VerkleNode::new(0, 0, total, NodeKind::Balance, None);
    nodes.push(total_node);
    let vectors = liabilities.clone();
    for idx in 1..liabilities.len() {
        let l = liabilities[idx];
        let node: VerkleNode = match idx % 2 { // even positions store liability
            0 => VerkleNode { 
                    id: vectors[idx - 1],
                    idx: idx,
                    value: l, 
                    kind: NodeKind::Balance, 
                    children: None 
                },
            _ => VerkleNode { // odd positions store id
                    id: vectors[idx],
                    idx: idx,
                    value: 0, 
                    kind: NodeKind::UserId, 
                    children: None 
                }
        };
        nodes.push(node);
    }
    match children {
        None => {}
        Some(children) => {
            let mut idx = nodes.len();
            for child in children {
                let mut node = child.clone();
                match child.kind {
                    NodeKind::Balance | NodeKind::UserId | NodeKind::ComHash => {}
                    NodeKind::Poly(poly_proof) => {
                        // insert the node that contains the hash value of the commitment
                        let hash_value = calculate_hash(&poly_proof.com_p);
                        let node = VerkleNode {
                            id: hash_value,
                            idx: idx,
                            value: 0,
                            kind: NodeKind::ComHash,
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

    let max_degree = ((liabilities.len() - 1) / 2 * MAX_BITS + 1).checked_next_power_of_two().expect("");
    let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).expect("Setup failed");

    VerkleNode::from(&pcs, liabilities.clone(), None, MAX_BITS).expect("Group setup failed")
}

#[test]
fn test_verkle_node_from_terminal_nodes() {
    use ark_std::test_rng;
    use ark_ff::{FftField, Field};

    const MAX_BITS: usize = 16;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    let max_degree = ((liabilities.len() - 1) / 2 * MAX_BITS + 1).checked_next_power_of_two().expect("");
    let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).expect("Setup failed");

    let root = VerkleNode::from(&pcs, liabilities.clone(), None, MAX_BITS).expect("Node setup failed");
    assert_eq!(root.value, 80);

    let aux_vec = compute_aux_vector(&liabilities, MAX_BITS);

    match root.kind {
        NodeKind::Balance | NodeKind::UserId | NodeKind::ComHash => { assert!(false) }
        NodeKind::Poly(poly_proof) => {
            let domain_size = aux_vec.len().checked_next_power_of_two().unwrap();
            let omega = F::get_root_of_unity(domain_size as u64).unwrap();
            for idx in 0..liabilities.len() {
                let point = omega.pow(&[idx as u64]);
                let target = F::from(liabilities[idx]);
                let proof = poly_proof.proofs[idx].witness_p;
                let result = Verifier::check(&pcs, &poly_proof.com_p, point, target, &proof).expect("");
                assert!(result);
            }
        }
    };
}

#[test]
fn test_verkle_group_intermediate_nodes() {
    use ark_std::test_rng;
    use ark_ff::{FftField, Field};

    const MAX_BITS: usize = 16;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    let node_1 = generate_verkle_node();
    let node_2 = generate_verkle_node();
    let nodes = [node_1, node_2].to_vec();

    let max_degree = 256;
    let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).expect("Setup failed");

    let root = VerkleNode::from(&pcs, [].to_vec(), Some(nodes.clone()), MAX_BITS).expect("Root setup failed");
    assert_eq!(root.value, 160);

    let root = VerkleNode::from(&pcs, liabilities.clone(), Some(nodes.clone()), MAX_BITS).expect("Root setup failed");
    assert_eq!(root.value, 240);

    match root.kind {
        NodeKind::Balance | NodeKind::UserId | NodeKind::ComHash => { assert!(false) }
        NodeKind::Poly(poly) => {
            let comm = poly.com_p;
            let proofs = poly.proofs;
            let children = root.children.unwrap();
            let omega = F::get_root_of_unity(poly.p.coeffs.len() as u64).unwrap();
            for idx in 1..liabilities.len() - 1 {
                let proof = &proofs[idx];
                let point = omega.pow(&[idx as u64]);
                let target = F::from(liabilities[idx]);
                let result = Verifier::check(&pcs, &comm, point, target, &proof.witness_p).expect("");
                assert!(result);
            }

            for idx in (liabilities.len()..liabilities.len() + nodes.len() * 2 - 1).step_by(2) {
                let node: &VerkleNode = &children[idx];
                match &node.kind {
                    NodeKind::Balance | NodeKind::UserId | NodeKind::ComHash => {}
                    NodeKind::Poly(child_poly) => {
                        let proof: Proof<Bls12<Config>> = proofs[idx].witness_p;
                        let hash_value_of_com_p = calculate_hash(&child_poly.com_p);
                        let point_com = omega.pow(&[idx as u64]);
                        let result = Verifier::check(&pcs, &comm, point_com, F::from(hash_value_of_com_p), &proof).expect("");
                        assert!(result);
                    }
                }
                let node: &VerkleNode = &children[idx + 1];
                let proof: Proof<Bls12<Config>> = proofs[idx + 1].witness_p;
                let point_value = omega.pow(&[(idx + 1) as u64]);
                let result = Verifier::check(&pcs, &comm, point_value, F::from(node.value), &proof).expect("");
                assert!(result);
            }
        }
    }
}
