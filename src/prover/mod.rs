use std::collections::HashMap;

use ark_ec::bls12::Bls12;
use ark_ec::scalar_mul::fixed_base::FixedBase;
use ark_ec::{VariableBaseMSM, CurveGroup, AffineRepr};
use ark_ec::pairing::Pairing;
use ark_poly::{Radix2EvaluationDomain, EvaluationDomain, DenseUVPolynomial, Polynomial};
use ark_poly_commit::{Evaluations, PolynomialCommitment};
use ark_poly_commit::kzg10::{KZG10, Commitment, Randomness, UniversalParams, Powers, VerifierKey, Proof};
use ark_std::borrow::Cow;
use ark_bls12_381::{Bls12_381, Config, G2Affine};
use ark_bls12_381::Fr as F;
use ark_std::{fmt, vec::Vec, start_timer, end_timer};
use ark_poly::univariate::DensePolynomial;
use ark_ff::PrimeField;

use crate::Error;
use crate::common::calculate_hash;
use crate::utils::{interpolate_poly, compute_aux_vector};
use crate::verkle_tree::tree::{VerkleNode, ProofIdNode, ProofValueNode};

pub mod data_structures;
use data_structures::*;

pub mod solvency;
pub mod constraints;

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

type D = Radix2EvaluationDomain::<F>;

impl Prover {
    pub fn setup(
        liabilities: &Vec<u64>,
        max_bits: usize,
    ) -> Result<Self, Error> {
        let aux_vec = compute_aux_vector(&liabilities, max_bits);
        let domain = D::new(aux_vec.len()).expect("Unsupported domain length");
        let p = interpolate_poly(&liabilities, domain);
        let i = interpolate_poly(&aux_vec, domain);
        Ok(Self { max_bits, p, i, liabilities: liabilities.to_vec(), aux_vec, domain })
    }

    pub fn commit(
        &self, 
        poly: &UniPoly_381,
        pcs: &UniversalParams<Bls12_381>,
    ) -> Result<(Commitment<Bls12_381>, Randomness<F, UniPoly_381>), Error> {
        let max_degree = poly.coeffs.len().checked_next_power_of_two().expect("Unsupported degree");
        let powers_of_g = pcs.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| pcs.powers_of_gamma_g[&i])
            .collect();
        let powers = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };
        let (com, r) = KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &poly, None, None).expect("Commitment failed");
        Ok((com, r))
    }

    pub fn compute_proof(
        poly: &UniPoly_381,
        pcs: &UniversalParams<Bls12_381>,
        point: F,
        rand: Randomness<F, UniPoly_381>,
    ) -> Result<Proof<Bls12_381>, Error> {
        let max_degree = poly.coeffs.len().checked_next_power_of_two().expect("Unsupported degree");
        let powers_of_g = pcs.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| pcs.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };
        let (witness, hiding_witness_poly): (UniPoly_381, Option<UniPoly_381>) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(poly, point, &rand).unwrap();
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness);
        let witness_comm_time = start_timer!(|| "Computing commitment to witness polynomial");
        let mut w = <<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );
        end_timer!(witness_comm_time);

        let random_v = if let Some(hiding_witness_polynomial) = hiding_witness_poly {
            let blinding_p = &rand.blinding_polynomial;
            let blinding_eval_time = start_timer!(|| "Evaluating random polynomial");
            let blinding_evaluation = blinding_p.evaluate(&point);
            end_timer!(blinding_eval_time);

            let random_witness_coeffs = convert_to_bigints(&hiding_witness_polynomial.coeffs());
            let witness_comm_time =
                start_timer!(|| "Computing commitment to random witness polynomial");
            w += &<<Bls12<ark_bls12_381::Config> as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
                &powers.powers_of_gamma_g,
                &random_witness_coeffs,
            );
            end_timer!(witness_comm_time);
            Some(blinding_evaluation)
        } else {
            None
        };
    
        let proof = Proof {
            w: w.into_affine(),
            random_v: random_v,
        };
        Ok(proof)
    }

    pub fn generate_grand_proof(
        root: &VerkleNode,
    ) -> HashMap::<u64, SolProof> {
        let all_paths = VerkleNode::generate_auth_path(&root, &[].to_vec());
        let mut all_proofs = HashMap::<u64, SolProof>::new();
        for (user_id, path) in all_paths {
            let iterator = path.clone();
            let proof_root = root.to_value_node().expect("");
            let mut nodes = Vec::<(ProofIdNode, ProofValueNode)>::new();
            let mut children = root.children.as_ref().unwrap();
            for idx in iterator {
                if idx == 0 {
                    continue;
                }
                let comm_hash_child = &children[(idx - 1) as usize];
                let comm_hash_node = comm_hash_child.to_id_node().expect("");
                let comm_child = &children[idx as usize];
                let proof_node = comm_child.to_value_node().expect("");
                nodes.push((comm_hash_node, proof_node));
                if comm_child.children.is_none() {
                    break;
                }
                children = comm_child.children.as_ref().unwrap();
            }
            nodes.reverse();
            let proof = SolProof { root: proof_root, children: nodes };
            all_proofs.insert(user_id, proof);
        }
        all_proofs
    }

    fn extend_liabilities(
        liabilities: &Vec<u64>,
        num_of_dummy_vecs: u32,
    ) -> Vec<u64> {
        use uuid::Uuid;
        let mut vec = liabilities.clone();
        for _ in 0..num_of_dummy_vecs {
            let uid = Uuid::new_v4().as_u128();
            let hash_uid = calculate_hash(&uid);
            vec.push(hash_uid);
            vec.push(0);
        }
        vec
    }
}

impl fmt::Debug for Prover {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Prover")
            .finish()
    }
}

fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField, P: DenseUVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let to_bigint_time = start_timer!(|| "Converting polynomial coeffs to bigints");
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();
    end_timer!(to_bigint_time);
    coeffs
}

#[test]
fn test_proof() {
    use ark_std::test_rng;
    use ark_ec::bls12::Bls12;
    use ark_ff::FftField;
    use ark_ff::Field;
    use ark_std::Zero;

    const MAX_BITS: usize = 16;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];

    let prover = Prover::setup(&liabilities, MAX_BITS).unwrap();
    let pcs: UniversalParams<Bls12<ark_bls12_381::Config>> = KZG10::<Bls12_381, UniPoly_381>::setup(prover.p.coeffs.len().checked_next_power_of_two().unwrap(), true, rng).expect("Setup failed");
    let max_degree = prover.p.coeffs.len().checked_next_power_of_two().unwrap();
    let powers_of_g = pcs.powers_of_g[..=max_degree].to_vec();
    let powers_of_gamma_g = (0..=max_degree)
        .map(|i| pcs.powers_of_gamma_g[&i])
        .collect();
    let powers: Powers<Bls12_381> = Powers {
        powers_of_g: Cow::Owned(powers_of_g),
        powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
    };

    let (com, r) = prover.commit(&prover.p.clone(), &pcs.clone()).expect("Commitment failed");
    let point = F::from(2);
    let value = prover.p.evaluate(&point);
    let proof = Prover::compute_proof(&prover.p, &pcs, point, r).expect("Computing proof failed");
    let vk = VerifierKey::<Bls12_381> {
        g: pcs.powers_of_g[0],
        gamma_g: pcs.powers_of_gamma_g[&0],
        h: pcs.h,
        beta_h: pcs.beta_h,
        prepared_h: pcs.prepared_h.clone(),
        prepared_beta_h: pcs.prepared_beta_h.clone(),
    };
    let result = KZG10::<Bls12_381, UniPoly_381>::check(&vk, &com, point, value, &proof).expect("Checking proof failed");
    assert!(result);
}
