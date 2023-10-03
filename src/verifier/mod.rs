use std::collections::HashMap;

use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{kzg10::{KZG10, VerifierKey, Commitment, Proof, UniversalParams}, Error};
use ark_std::{test_rng, UniformRand};
use ark_bls12_381::{Fr as F, Bls12_381};

use crate::verkle_tree::tree::*;

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

pub struct Verifier {

}

impl Verifier {
    pub fn verify(path: &HashMap<u64, Vec<u64>>, user_id: u64, balance: u64, root: &VerkleNode) {
        let mut path: Vec<u64>= path.get(&user_id).expect("UserId not found").clone();
        path.reverse();
        let nodes = Verifier::generate_nodes_from(path, &root);
        for (id_node, value_node) in nodes {
            println!("{} - {}", id_node.kind, value_node.kind);
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
        nodes.push((id_node.clone(), value_node.clone()));
        let other_nodes = Verifier::generate_nodes_from(path, value_node);
        nodes.extend(other_nodes);
        nodes
    }
}