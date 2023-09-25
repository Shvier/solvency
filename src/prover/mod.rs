use crate::Error;
use ark_ec::{VariableBaseMSM, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_poly::{Radix2EvaluationDomain, Evaluations, EvaluationDomain, DenseUVPolynomial, Polynomial};
use ark_poly_commit::kzg10::{KZG10, Commitment, Randomness, UniversalParams, Powers, VerifierKey, Proof};
use ark_std::borrow::Cow;
use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr as F;
use ark_std::{fmt, vec::Vec, start_timer, end_timer};
use ark_poly::univariate::DensePolynomial;
use ark_ff::{PrimeField};

mod utils;
use utils::*;

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

type D = Radix2EvaluationDomain::<F>;

struct Prover<'a> {
    pcs: UniversalParams<Bls12_381>,
    max_bits: usize,
    max_degree: usize,
    p: DensePolynomial<F>,
    powers: Powers<'a, Bls12_381>,
}

impl Prover<'_> {
    pub fn setup(
        domain: D,
        pcs: UniversalParams<Bls12_381>,
        liabilities: Vec<u64>,
        max_bits: usize,
        max_degree: usize,
    ) -> Result<Self, Error> {
        let p = interpolate_poly(&liabilities, domain);
        let aux_vec = compute_aux_vector(&liabilities, max_bits);
        let powers_of_g = pcs.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| pcs.powers_of_gamma_g[&i])
            .collect();
        let powers = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };
        Ok(Self { pcs, max_bits, max_degree, p, powers })
    }

    pub fn commit(
        &self, 
    ) -> Result<(Commitment<Bls12_381>, Randomness<F, DensePolynomial<F>>), Error> {
        let (com, r) = KZG10::<Bls12_381, UniPoly_381>::commit(&self.powers, &self.p, None, None).expect("Commitment failed");
        Ok((com, r))
    }

    pub fn compute_proof(
        &self, 
        point: F,
        r: Randomness<F, DensePolynomial<F>>,
    ) -> Result<(Proof<Bls12_381>, VerifierKey<Bls12_381>), Error> {
        let params = &self.pcs;
        let powers = &self.powers;
        let (witness, _): (UniPoly_381, Option<UniPoly_381>) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(&self.p, point, &r).unwrap();
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness);
        let witness_comm_time = start_timer!(|| "Computing commitment to witness polynomial");
        let w = <<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );
        end_timer!(witness_comm_time);
        let vk = VerifierKey::<Bls12_381> {
            g: params.powers_of_g[0],
            gamma_g: params.powers_of_gamma_g[&0],
            h: params.h,
            beta_h: params.beta_h,
            prepared_h: params.prepared_h.clone(),
            prepared_beta_h: params.prepared_beta_h.clone(),
        };
    
        let proof = Proof {
            w: w.into_affine(),
            random_v: None,
        };
        Ok((proof, vk))
    }    
}

impl fmt::Debug for Prover<'_> {
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
fn test_setup() {
    use ark_std::test_rng;
    
    type D = Radix2EvaluationDomain::<F>;
    const MAX_BITS: usize = 16;
    const MAX_DEGREE: usize = 64;

    let rng = &mut test_rng();
    let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(MAX_DEGREE, false, rng).expect("Setup failed");

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let domain = D::new(liabilities.len()).expect("Unsupported domain length");
    let prover = Prover::setup(domain, pcs, liabilities, MAX_BITS, MAX_DEGREE).unwrap();
    let (com, r) = prover.commit().expect("Commitment failed");
    let point = F::from(2);
    let value = prover.p.evaluate(&point);
    let (proof, vk) = prover.compute_proof(point, r).expect("Computing proof failed");
    let result = KZG10::<Bls12_381, UniPoly_381>::check(&vk, &com, point, value, &proof).expect("Checking proof failed");
    assert!(result);
}
