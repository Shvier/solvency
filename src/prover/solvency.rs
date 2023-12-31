use crate::utils::{substitute_x, compute_aux_vector, add_assign};

use super::{data_structures::*, D, constraints::PolyCopyConstraints};

use ark_ff::{Field, FftField};
use ark_bls12_381::Fr as F;
use ark_poly::{EvaluationDomain, univariate::DensePolynomial, Polynomial, Evaluations, Radix2EvaluationDomain, DenseUVPolynomial};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_std::{test_rng, UniformRand};

impl Prover {
    pub fn compute_w1(&self) -> DensePolynomial<F> {
        let i = &self.i;

        let scale_factor = self.max_bits + 1;
        let shift = self.max_bits + 1;
        // i(scale_factor * x + 1)
        let i_scaled_1 = substitute_x::<F, D>(&i, scale_factor, 1); 
        // i(scale_factor * x + scale_factor)
        let i_scaled_sf = substitute_x::<F, D>(&i, scale_factor, shift);
        // i(scale_factor * x + (scale_factor + 1))
        let i_scaled_sf_1 = substitute_x::<F, D>(&i, scale_factor, shift + 1);
        
        &(&i_scaled_1 - &i_scaled_sf) - &i_scaled_sf_1
    }

    pub fn compute_w2(&self) -> DensePolynomial<F> {
        let scale_factor = self.max_bits + 1;
        let i = &self.i;
        let omega = F::get_root_of_unity(self.domain.size).expect("Unsupported domain size");
        let aux_vec = &self.aux_vec;

        // i(x + 1)
        let i_shifted_1 = substitute_x::<F, D>(&i, 1, 1);
        // i(x) * 2
        let i_doubled = i * F::from(2);
        // i(x + 1) - i(x) * 2
        let first_term = &i_shifted_1 - &i_doubled;
        // i(x) * 2 + 1
        let i_doubled_1 = add_assign(&i_doubled, F::from(1), false);
        // i(x + 1) - (i(x) * 2 + 1)
        let second_term = &i_shifted_1 - &i_doubled_1;

        let power = aux_vec.len();
        let mut powers_of_omega = vec![F::from(0); power];
        for idx in (0..power).step_by(scale_factor) {
            powers_of_omega[idx] = omega.pow(&[idx as u64]);
        }
        // omega^(scale_factor * i)
        let omega_sf_power = Evaluations::<F, D>::from_vec_and_domain(powers_of_omega.clone(), self.domain).interpolate();

        let mut powers_of_omega = vec![F::from(0); power];
        for idx in (1..power).step_by(scale_factor) {
            powers_of_omega[idx] = omega.pow(&[idx as u64]);
        }
        // omega^(scale_factor * i + 1)
        let omega_sf_power_1 = Evaluations::<F, D>::from_vec_and_domain(powers_of_omega.clone(), self.domain).interpolate();

        // f(x) = x
        let linear = DensePolynomial::<F>::from_coefficients_vec([F::from(0), F::from(1)].to_vec());

        // X - omega^(scale_factor * i)
        let third_term = &linear - &omega_sf_power;
        // X - omega^(scale_factor * i + 1)
        let fourth_term = &linear - &omega_sf_power_1;

        let mut w2 = &first_term * &second_term;
        w2 = &w2 * &third_term;
        w2 = &w2 * &fourth_term;
        w2
    }

    pub fn compute_w3(&self) -> DensePolynomial<F> {
        let scale_factor = self.max_bits + 1;
        let i = &self.i;
        let p = &self.p;

        // i(scale_factor * x)
        let i_scaled = substitute_x::<F, D>(&i, scale_factor, 0);
        // p(omega^(2i)), all the values at even positions, that is, each user balance
        let p_even = substitute_x::<F, D>(&p, 2, 0);

        &i_scaled - &p_even
    }    
}

#[test]
fn test_compute_w1() {
    use ark_ff::{FftField, Field};
    use ark_poly::Polynomial;
    use ark_std::Zero;

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let aux_vec = compute_aux_vector(&liabilities, 16);
    let domain = D::new(aux_vec.len()).expect("Unsupported domain length");
    let prover = generate_prover();
    let w1 = prover.compute_w1();
    let root_of_unity = F::get_root_of_unity(domain.size).unwrap();
    for idx in 0..liabilities.len() {
        let point = root_of_unity.pow(&[idx as u64]);
        assert!(w1.evaluate(&point).is_zero());
    }
}

#[test]
fn test_compute_w2() {
    use ark_ff::{FftField, Field};
    use ark_poly::Polynomial;
    use ark_std::Zero;

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let aux_vec = compute_aux_vector(&liabilities, 16);
    let domain = D::new(aux_vec.len()).expect("Unsupported domain length");
    let prover = generate_prover();
    let w2 = prover.compute_w2();
    let root_of_unity = F::get_root_of_unity(domain.size).unwrap();
    for idx in 0..liabilities.len() {
        let point = root_of_unity.pow(&[idx as u64]);
        assert!(w2.evaluate(&point).is_zero());
    }
}

#[test]
fn test_compute_w3() {
    use ark_ff::{FftField, Field};
    use ark_poly::Polynomial;
    use ark_std::Zero;

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let aux_vec = compute_aux_vector(&liabilities, 16);
    let domain = D::new(aux_vec.len()).expect("Unsupported domain length");
    let prover = generate_prover();
    let w3 = prover.compute_w3();
    let root_of_unity = F::get_root_of_unity(domain.size).unwrap();
    for idx in 0..liabilities.len() {
        let point = root_of_unity.pow(&[idx as u64]);
        let eval = w3.evaluate(&point);
        assert!(eval.is_zero());
    }
}
