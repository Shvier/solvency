use ark_ec::{VariableBaseMSM, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_poly::{Radix2EvaluationDomain, Evaluations, EvaluationDomain, DenseUVPolynomial, Polynomial};
use ark_poly_commit::kzg10::{KZG10, Commitment, Randomness, UniversalParams, Powers, VerifierKey, Proof};
use ark_std::borrow::Cow;
use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr as F;
use ark_std::{fmt, vec::Vec, start_timer, end_timer, rand::Rng, UniformRand};
use ark_poly::univariate::DensePolynomial;
use ark_ff::{PrimeField};

use crate::Error;
use crate::common::calculate_hash;

pub mod data_structures;
use data_structures::*;

pub mod solvency;

mod utils;
use utils::*;

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

type D = Radix2EvaluationDomain::<F>;

impl Prover {
    pub fn setup(
        liabilities: &Vec<u64>,
        max_bits: usize,
    ) -> Result<Self, Error> {
        let extended = Prover::extend_liabilities(liabilities, 10);
        println!("{:?}", extended);
        let domain = D::new(liabilities.len()).expect("Unsupported domain length");
        let p = interpolate_poly(&liabilities, domain);
        let aux_vec = compute_aux_vector(&liabilities, max_bits);
        let domain = D::new(aux_vec.len()).expect("Unsupported domain length");
        let i = interpolate_poly(&aux_vec, domain);
        Ok(Self { max_bits, p, i, liabilities: liabilities.to_vec(), aux_vec })
    }

    pub fn commit<R: Rng>(
        &self, 
        poly: &DensePolynomial<F>,
        rng: &mut R,
    ) -> Result<(Commitment<Bls12_381>, Randomness<F, DensePolynomial<F>>), Error> {
        let max_degree = poly.coeffs.len().checked_next_power_of_two().expect("Unsupported degree");
        let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).expect("Setup failed");
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

    pub fn compute_proof<R: Rng>(
        &self, 
        point: F,
        r: Randomness<F, DensePolynomial<F>>,
        rng: &mut R,
        max_degree: usize,
    ) -> Result<(Proof<Bls12_381>, VerifierKey<Bls12_381>), Error> {
        let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).expect("Setup failed");
        let powers_of_g = pcs.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| pcs.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };
        let (witness, _): (UniPoly_381, Option<UniPoly_381>) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(&self.p, point, &r).unwrap();
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness);
        let witness_comm_time = start_timer!(|| "Computing commitment to witness polynomial");
        let w = <<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );
        end_timer!(witness_comm_time);
        let vk = VerifierKey::<Bls12_381> {
            g: pcs.powers_of_g[0],
            gamma_g: pcs.powers_of_gamma_g[&0],
            h: pcs.h,
            beta_h: pcs.beta_h,
            prepared_h: pcs.prepared_h.clone(),
            prepared_beta_h: pcs.prepared_beta_h.clone(),
        };
    
        let proof = Proof {
            w: w.into_affine(),
            random_v: None,
        };
        Ok((proof, vk))
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
    
    type D = Radix2EvaluationDomain::<F>;
    const MAX_BITS: usize = 16;
    const MAX_DEGREE: usize = 64;

    let rng = &mut test_rng();

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let domain = D::new(liabilities.len()).expect("Unsupported domain length");
    let prover = Prover::setup(&liabilities, MAX_BITS).unwrap();
    let (com, r) = prover.commit(&prover.p.clone(), rng).expect("Commitment failed");
    let point = F::from(2);
    let value = prover.p.evaluate(&point);
    let (proof, vk) = prover.compute_proof(point, r, rng, MAX_DEGREE).expect("Computing proof failed");
    let result = KZG10::<Bls12_381, UniPoly_381>::check(&vk, &com, point, value, &proof).expect("Checking proof failed");
    assert!(result);
}
