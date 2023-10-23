use std::ops::Sub;

use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, Polynomial};
use ark_ff::{FftField, PrimeField};
use ark_std::rand::Rng;
use ark_std::test_rng;
use ark_relations::r1cs::{
    ConstraintSystem,
    ConstraintSynthesizer,
    Result,
};

use crate::prover::constraints::PolyCopyConstraints;

pub fn compute_aux_vector(liabilities: &Vec<u64>, max_bits: usize) -> Vec<u64> {
    let mut vec = Vec::<u64>::new();
    if liabilities.len() <= 0 {
        return vec;
    }
    vec.push(liabilities[0]);
    vec.push(liabilities[0]);
    let mut remanent = liabilities[0];
    for i in (2..liabilities.len()).step_by(2) {
        let liability = liabilities[i];
        let bits = build_up_bits(liability, max_bits);
        vec.extend_from_slice(&bits);
        vec.push(remanent - liability);
        remanent -= liability;
    }
    vec
}

pub fn build_up_bits(value: u64, max_bits: usize) -> Vec<u64> {
    assert!(value <= 2_u64.pow(u32::try_from(max_bits).unwrap()));
    let mut bits: Vec<u64> = Vec::with_capacity(max_bits);
    for _ in 0..max_bits {
        bits.push(0);
    }
    let mut v = value;
    bits[max_bits - 1] = value;
    let mut i = bits.len() - 2;
    loop {
        bits[i] = v / 2;
        v = bits[i];
        if i == 0 {
            break;
        }
        i -= 1;
    }
    bits
}

pub fn interpolate_poly<
F: FftField,
D: EvaluationDomain<F>,
>(
    vectors: &Vec<u64>, 
    domain: D
) -> DensePolynomial<F> {
    let ff_vectors = vectors.into_iter().map(|v| {F::from(*v)}).collect();
    let evaluations = Evaluations::from_vec_and_domain(ff_vectors, domain);
    evaluations.interpolate()
}

pub fn substitute_x<
F: PrimeField,
D: EvaluationDomain<F>,
>(
    p: &DensePolynomial<F>, 
    scale: usize, 
    shift: usize,
) -> DensePolynomial<F> {
    let deg = p.coeffs.len();
    let domain = D::new(deg).unwrap();
    let mut new_evals = Vec::<F>::new();
    let root = F::get_root_of_unity(deg as u64).unwrap();
    let mut pos = shift;
    for _ in 0..deg {
        let point: F = root.pow(&[pos as u64]);
        let eval = p.evaluate(&point);
        new_evals.push(eval);
        pos = pos + scale;
    }
    let new_eval = Evaluations::<F, D>::from_vec_and_domain(new_evals, domain);
    let new_p = new_eval.interpolate();
    let result = constrain_polys(&p.coeffs, &new_p.coeffs, scale, shift);
    result.expect("Failed to prove copy constraints");
    new_p
}

pub fn constrain_polys<
F: PrimeField,
>(
    old_coeffs: &Vec<F>, 
    new_coeffs: &Vec<F>, 
    scale_factor: usize, 
    shift_factor: usize,
) -> Result<()> {
    let root_of_unity = F::get_root_of_unity(old_coeffs.len() as u64).expect("Cannot find root of unity");
    let mut rng = test_rng();
    let point = rng.gen_range(0..new_coeffs.len());
    let circuit = PolyCopyConstraints::<F> {
        point,
        root_of_unity,
        scale_factor,
        shift_factor,
        old_coeffs: old_coeffs.to_vec(),
        new_coeffs: new_coeffs.to_vec(),
    };
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs)
}

pub fn elementwise_subtraction<N, IA, IB, F>(a: IA, b: IB) -> F
where
    N: Sub,
    IA: IntoIterator<Item = N>,
    IB: IntoIterator<Item = N>,
    F: FromIterator<N> + FromIterator<<N as Sub>::Output> {
    a.into_iter().zip(b).map(|(a, b)| a - b).collect()
}

pub fn add_assign<
F: PrimeField,
>(p: &DensePolynomial<F>, element: F, negative: bool) -> DensePolynomial<F> {
    let mut new_p = p.clone();
    if negative {
        new_p.coeffs[0] -= element;
    } else {
        new_p.coeffs[0] += element;
    }
    new_p
}

#[cfg(test)]
fn compare_vecs(va: &[u64], vb: &[u64]) -> bool {
    (va.len() == vb.len()) &&
     va.iter()
       .zip(vb)
       .all(|(a,b)| *a == *b)
}

#[cfg(test)]
fn get_aux_vector() -> Vec<u64> {
    let total = vec![80, 80];
    let first = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 5, 10, 20, 60];
    let second = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 6, 12, 25, 50, 10];
    let third = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 5, 10, 0];
    [total, first, second, third].concat()
}

#[test]
fn test_compute_aux_vector() {
    let vec = get_aux_vector();
    let liabilities = vec![80, 1, 20, 2, 50, 3, 10];
    let aux_vec = compute_aux_vector(&liabilities, 15);
    assert!(compare_vecs(&aux_vec, &vec));
}

#[test]
fn test_build_up_bits() {
    let bits_8 = [0, 0, 1, 2, 5, 10, 20];
    let bits = build_up_bits(20, 7);
    assert!(compare_vecs(&bits_8, &bits));

    let bits_16 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 6, 12, 25, 50];
    let bits = build_up_bits(50, 15);
    assert!(compare_vecs(&bits_16, &bits));
}

#[test]
fn test_substitute_x() {
    use ark_bls12_381::Fr as F;
    use ark_ff::Field;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain, Polynomial};
    use ark_std::test_rng;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

    use crate::prover::constraints::PolyCopyConstraints;

    type D = Radix2EvaluationDomain::<F>;

    const MUL: u64 = 16;
    let i_vec = get_aux_vector();
    let domain = D::new(i_vec.len()).unwrap();
    let domain_size = domain.size as u64;
    let root_of_unity = F::get_root_of_unity(domain_size).unwrap();
    let raise = |root: F, power: u64| -> F {
        root.pow(&[power])
    };

    let i = interpolate_poly(&i_vec, domain);
    let i_16x = substitute_x::<F, D>(&i, MUL as usize, 0);
    let i_16x_15 = substitute_x::<F, D>(&i, MUL as usize, 15);

    assert_eq!(i.evaluate(&raise(root_of_unity, 16)), i_16x.evaluate(&raise(root_of_unity, 1)));

    assert_eq!(i.evaluate(&raise(root_of_unity, 32)), i_16x.evaluate(&raise(root_of_unity, 2)));

    assert_eq!(i.evaluate(&raise(root_of_unity, 15)), i_16x_15.evaluate(&raise(root_of_unity, 0)));

    assert_eq!(i.evaluate(&raise(root_of_unity, 31)), i_16x_15.evaluate(&raise(root_of_unity, 1)));

    let mut rng = test_rng();
    let point = rng.gen_range(0..i.coeffs.len());

    let constraints = PolyCopyConstraints::<F> {
        point,
        root_of_unity,
        scale_factor: 16,
        shift_factor: 15,
        old_coeffs: i.coeffs,
        new_coeffs: i_16x_15.coeffs,
    };
    let cs = ConstraintSystem::new_ref();
    constraints.generate_constraints(cs).expect("");
}