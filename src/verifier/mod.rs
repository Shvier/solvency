use std::collections::HashMap;

use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{kzg10::{KZG10, VerifierKey, Commitment, Proof, UniversalParams}, Error};
use ark_std::{test_rng, UniformRand};
use ark_bls12_381::{Fr as F, Bls12_381};
use ark_ff::{FftField, Field};

use crate::{verkle_tree::tree::*, common::calculate_hash};

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

pub struct Verifier {

}

impl Verifier {
    pub fn verify(
        path: &HashMap<u64, Vec<u64>>, 
        user_id: u64, 
        balance: u64, 
        root: &VerkleNode, 
        pcs: &UniversalParams<Bls12_381>
    ) {
        let mut path: Vec<u64>= path.get(&user_id).expect("UserId not found").clone();
        path.reverse();
        let nodes = Verifier::generate_nodes_from(path.clone(), &root);
        let (id_node, value_node) = &nodes[0];
        assert_eq!(id_node.id, user_id);
        assert_eq!(value_node.value, balance);
        for idx in 1..nodes.len() {
            let cur = &nodes[idx];
            let prev = &nodes[idx - 1];
            let degree = cur.1.children.as_deref().unwrap().len().checked_next_power_of_two().unwrap();
            let omega = F::get_root_of_unity(degree as u64).unwrap();
            match &cur.1.kind {
                NodeKind::Poly(comm, proofs, _) => {
                    let hash_of_comm = calculate_hash(comm);
                    assert_eq!(hash_of_comm, cur.0.id);
                    let id_idx = prev.0.idx;
                    let id_proof = proofs[id_idx];
                    let id_check = Verifier::check(pcs, comm, omega.pow(&[id_idx as u64]), F::from(prev.0.id), &id_proof).expect("");
                    assert!(id_check);
                    let value_idx = prev.1.idx;
                    let value_proof = proofs[value_idx];
                    let value_check = Verifier::check(pcs, comm, omega.pow(&[value_idx as u64]), F::from(prev.1.value), &value_proof).expect("");
                    assert!(value_check);
                }
                _ => {}
            }
        }
    }

    pub fn check(
        pcs: &UniversalParams<Bls12_381>,
        comm: &Commitment<Bls12_381>,
        point: F,
        value: F,
        proof: &Proof<Bls12_381>,
    ) -> Result<bool, Error> {
        let vk = VerifierKey::<Bls12_381> {
            g: pcs.powers_of_g[0],
            gamma_g: pcs.powers_of_gamma_g[&0],
            h: pcs.h,
            beta_h: pcs.beta_h,
            prepared_h: pcs.prepared_h.clone(),
            prepared_beta_h: pcs.prepared_beta_h.clone(),
        };
        KZG10::<Bls12_381, UniPoly_381>::check(&vk, comm, point, value, proof)
    }
}

impl Verifier {
    #[inline]
    fn generate_nodes_from(mut path: Vec<u64>, root: &VerkleNode) -> Vec<(VerkleNode, VerkleNode)> {
        if path.len() <= 0 {
            return [].to_vec();
        }
        let pos = path.pop().unwrap() as usize;
        let children = root.children.as_deref().expect("Root is empy");
        let value_node = &children[pos];
        let id_node = &children[pos - 1];
        let mut nodes = Vec::<(VerkleNode, VerkleNode)>::new();
        let other_nodes = Verifier::generate_nodes_from(path, value_node);
        nodes.extend(other_nodes);
        nodes.push((id_node.clone(), value_node.clone()));
        nodes
    }
}