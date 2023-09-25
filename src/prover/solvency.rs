use super::{data_structures::*, utils::*, D};

use ark_bls12_381::Fr as F;
use ark_poly::{EvaluationDomain, univariate::DensePolynomial};

impl Prover<'_> {
    pub fn compute_w1(&self) -> DensePolynomial<F> {
        let max_bits = self.max_bits;
        let i = &self.i;

        let scale_factor = max_bits + 1;
        // i(scale_factor * x + 1)
        let i_scaled_1 = substitute_x::<F, D>(&i, scale_factor, 1); 
        // i(scale_factor * x + scale_factor)
        let i_scaled_sf = substitute_x::<F, D>(&i, scale_factor, scale_factor);
        // i(scale_factor * x + (scale_factor + 1))
        let i_scaled_sf_1 = substitute_x::<F, D>(&i, scale_factor, scale_factor + 1);
        &(&i_scaled_1 - &i_scaled_sf) - &i_scaled_sf_1
    }

    pub fn compute_w2(&self) {
        let scale_factor = self.max_bits + 1;
        let i = &self.i;

        // i(scale_factor * x)
        let i_scaled = substitute_x::<F, D>(&i, scale_factor, 0);
    }
}

#[test]
fn test_compute_w1() {
    use ark_ff::{FftField, Field};
    use ark_poly::Polynomial;
    use ark_std::Zero;

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let aux_vec = compute_aux_vector(&liabilities, 15);
    let domain = D::new(liabilities.len()).expect("Unsupported domain length");
    let prover = generate_prover();
    let w1 = prover.compute_w1();
    let root_of_unity = F::get_root_of_unity(domain.size).unwrap();
    for idx in 0..aux_vec.len() {
        let point = root_of_unity.pow(&[idx as u64]);
        assert!(w1.evaluate(&point).is_zero());
    }
}