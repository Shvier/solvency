use ark_poly::Radix2EvaluationDomain;
use ark_bls12_381::Fr as F;
use ark_poly::univariate::DensePolynomial;

pub struct Prover {
    pub domain: Radix2EvaluationDomain::<F>,
    pub max_bits: usize,
    pub p: DensePolynomial<F>,
    pub i: DensePolynomial<F>,
    pub liabilities: Vec<u64>,
    pub aux_vec: Vec<u64>,
}

#[cfg(test)]
pub fn generate_prover() -> Prover {
    use ark_poly::EvaluationDomain;

    type D = Radix2EvaluationDomain::<F>;

    const MAX_BITS: usize = 16;

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let domain = D::new(liabilities.len()).expect("Unsupported domain length");

    Prover::setup(domain, &liabilities, MAX_BITS).unwrap()
}
