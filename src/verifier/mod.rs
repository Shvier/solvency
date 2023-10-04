use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{kzg10::{KZG10, VerifierKey, Commitment, UniversalParams, Proof}, Error};
use ark_bls12_381::{Fr as F, Bls12_381};
use ark_ff::{FftField, Field};

use crate::{verkle_tree::tree::*, common::calculate_hash, prover::data_structures::SolProof};

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

pub struct Verifier {

}

impl Verifier {
    pub fn verify(
        sol_proof: &SolProof,
        pcs: &UniversalParams<Bls12_381>,
        user_id: u64, 
        balance: u64, 
    ) {
        assert!(sol_proof.children.len() >= 2);
        let proof_nodes = &sol_proof.children;
        let self_node = &proof_nodes[0];
        assert_eq!(self_node.0.id, user_id);

        let (id_node, value_node) = &proof_nodes[1];
        match &value_node.kind {
            ProofValueNodeKind::Poly(comm, proofs, omega) => {
                let hash_of_comm = calculate_hash(&comm);
                assert_eq!(hash_of_comm, id_node.id);
                let user_id_idx = self_node.0.idx;
                let user_bal_idx = self_node.1.idx;
                let user_id_proof = proofs[user_id_idx];
                let user_bal_proof = proofs[user_bal_idx];
                let user_id_check = Verifier::check(pcs, &comm, omega.pow(&[user_id_idx as u64]), F::from(user_id), &user_id_proof).expect("");
                assert!(user_id_check);
                let user_bal_check = Verifier::check(pcs, &comm, omega.pow(&[user_bal_idx as u64]), F::from(balance), &user_bal_proof).expect("");
                assert!(user_bal_check);
            }
            ProofValueNodeKind::Balance => {}
        }

        for idx in 2..proof_nodes.len() {
            let (cur_id_node, cur_value_node) = &proof_nodes[idx];
            match &cur_value_node.kind {
                ProofValueNodeKind::Poly(comm, proofs, omega) => {
                    assert_eq!(cur_id_node.id, calculate_hash(&comm));
                    let (prev_id_node, prev_value_node) = &proof_nodes[idx - 1];
        
                    let id_idx: usize = prev_id_node.idx;
                    let id_proof = proofs[id_idx];
                    let id_check = Verifier::check(pcs, &comm, omega.pow(&[id_idx as u64]), F::from(prev_id_node.id), &id_proof).expect("");
                    assert!(id_check);
        
                    // TODO
                    // the verifying process is different from the above one
                    // let value_idx = prev_value_node.idx;
                    // let value_proof = proofs[value_idx];
                    // let value_check = Verifier::check(pcs, &comm, omega.pow(&[value_idx as u64]), F::from(prev_value_node.id), &value_proof).expect("");
                    // assert!(value_check);
                }
                ProofValueNodeKind::Balance => {}
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
