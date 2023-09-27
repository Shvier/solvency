use ark_poly::Radix2EvaluationDomain;
use ark_poly_commit::kzg10::{UniversalParams, Powers};
use ark_bls12_381::Bls12_381;
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
    use ark_std::test_rng;
    use ark_poly_commit::kzg10::KZG10;
    use ark_ec::pairing::Pairing;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

    type D = Radix2EvaluationDomain::<F>;
    type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

    const MAX_BITS: usize = 16;
    const MAX_DEGREE: usize = 64;

    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let domain = D::new(liabilities.len()).expect("Unsupported domain length");

    let rng = &mut test_rng();
    let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(MAX_DEGREE, false, rng).expect("Setup failed");
    Prover::setup(domain, pcs, &liabilities, MAX_BITS, MAX_DEGREE).unwrap()
}
