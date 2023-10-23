use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{kzg10::{KZG10, VerifierKey, Commitment, UniversalParams, Proof}, Error};
use ark_bls12_381::{Fr as F, Bls12_381};
use ark_ff::{FftField, Field};
use ark_std::{test_rng, rand::Rng, Zero};
use ark_poly::Polynomial;

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
        // check if the id of the first node matches the user id to ensure the following nodes are the proofs for this user
        let proof_nodes = &sol_proof.children;
        let self_node = &proof_nodes[0];
        assert_eq!(self_node.0.id, user_id);

        // check if the user id and the user balance are the evaluations of the commitment to P, the second node
        let (id_node, value_node) = &proof_nodes[1];
        match &value_node.kind {
            ProofValueNodeKind::Poly(poly_proof) => {
                let com_p = poly_proof.com_p;
                let omega = poly_proof.omega;
                let proofs = &poly_proof.proofs;
                let hash_of_comm = calculate_hash(&com_p);
                assert_eq!(hash_of_comm, id_node.id);
                let user_id_idx = self_node.0.idx;
                let user_bal_idx = self_node.1.idx;
                let user_id_proof = proofs[user_id_idx].witness_p;
                let user_bal_proof = proofs[user_bal_idx].witness_p;
                let user_id_check = Verifier::check(pcs, &com_p, omega.pow(&[user_id_idx as u64]), F::from(user_id), &user_id_proof).expect("");
                assert!(user_id_check);
                let user_bal_check = Verifier::check(pcs, &com_p, omega.pow(&[user_bal_idx as u64]), F::from(balance), &user_bal_proof).expect("");
                assert!(user_bal_check);
            }
            ProofValueNodeKind::Balance => {}
        }

        // recursively check the evaluations of current node at fixed positions are copied from the previous nodes
        for idx in 2..proof_nodes.len() {
            let (cur_id_node, cur_value_node) = &proof_nodes[idx];
            match &cur_value_node.kind {
                ProofValueNodeKind::Poly(cur_poly_proof) => {
                    let omega = cur_poly_proof.omega;
                    let cur_com_p = &cur_poly_proof.com_p;
                    let w = &cur_poly_proof.w;
                    let cur_proofs = &cur_poly_proof.proofs;
                    assert_eq!(cur_id_node.id, calculate_hash(&cur_com_p));
                    let (prev_id_node, prev_value_node) = &proof_nodes[idx - 1];
        
                    let id_idx: usize = prev_id_node.idx;
                    let id_proof = cur_proofs[id_idx].witness_p;
                    let id_check = Verifier::check(pcs, &cur_com_p, omega.pow(&[id_idx as u64]), F::from(prev_id_node.id), &id_proof).expect("");
                    assert!(id_check);

                    match &prev_value_node.kind {
                        ProofValueNodeKind::Poly(_) => {
                            let prev_comm_idx = prev_value_node.idx;
                            let proof_z = cur_poly_proof.proofs[prev_comm_idx].proof_z;
                            match proof_z {
                                Some(proof_z) => {
                                    let (com_z, witness_z) = proof_z;
                                    let z_vanishing_check = Verifier::check(pcs, &com_z, F::from(1), F::from(0), &witness_z).expect("");
                                    assert!(z_vanishing_check);
                                }
                                None => {}
                            }
                        }
                        ProofValueNodeKind::Balance => {}
                    }

                    // check if w is vanishing at any point in the domain
                    let mut rng = test_rng();
                    let rand_num = rng.gen_range(0..w.coeffs.len());
                    let point = omega.pow(&[rand_num as u64]);
                    let eval = w.evaluate(&point);
                    assert!(eval.is_zero());
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
