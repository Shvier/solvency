use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use ark_ec::{VariableBaseMSM, CurveGroup};
use ark_ff::PrimeField;
use ark_poly_commit::kzg10::{KZG10, Powers, VerifierKey, Proof};
use ark_bls12_381::Bls12_381;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Evaluations, Polynomial};
use ark_poly::univariate::DensePolynomial;
use ark_ec::pairing::Pairing;
use ark_std::{test_rng, start_timer, end_timer};
use ark_std::rand::Rng;
use ark_bls12_381::Fr as F;

type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

fn main() {
    const DEGREE: usize = 64;

    // KZG trusted setup
    let rng = &mut test_rng();
    let params = KZG10::<Bls12_381, UniPoly_381>::setup(DEGREE, false, rng).expect("Setup failed");
    let powers_of_g = params.powers_of_g[..=DEGREE].to_vec();
    let powers_of_gamma_g = (0..=DEGREE)
        .map(|i| params.powers_of_gamma_g[&i])
        .collect();
    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };

    // Convert liabilities into vectors and interpolate P
    type D = GeneralEvaluationDomain::<F>;
    let domain = D::new(53).unwrap();
    let vectors: Vec<F> = generate_liabilities().into_iter().map(|v| {F::from(v)}).collect();
    println!("number of vectors: {}", vectors.len());
    let evaluations = Evaluations::from_vec_and_domain(vectors, domain);

    let poly = evaluations.interpolate();
    
    println!("coeffs size: {}", poly.coeffs.len());

    // Commit to P
    let (com, r) = KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &poly, None, None).expect("Commitment failed");

    // The point at index 0
    let point = F::from(0);
    let value = poly.evaluate(&point);

    // Compute witness for the point
    let (witness, _): (UniPoly_381, Option<UniPoly_381>) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(&poly, point, &r).unwrap();

    let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness);
    let witness_comm_time = start_timer!(|| "Computing commitment to witness polynomial");
    let w = <<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
        &powers.powers_of_g[num_leading_zeros..],
        &witness_coeffs,
    );
    end_timer!(witness_comm_time);

    // Generate the proof
    let vk = VerifierKey {
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

    // Verify the proof
    let result = KZG10::<Bls12_381, UniPoly_381>::check(&vk, &com, point, value, &proof).unwrap();
    println!("{}", result);
}

fn compute_aux_vector(liabilities: &Vec<u64>, max_bits: usize) -> Vec<u64> {
    let mut vec = Vec::<u64>::new();
    vec.push(liabilities[0]);
    let mut remanent = liabilities[0];
    let mut i = 2; // index 1 is the first user's id
    while i < liabilities.len() {
        let liability = liabilities[i];
        let bits = build_up_bits(liability, max_bits);
        vec.extend_from_slice(&bits);
        vec.push(remanent - liability);
        remanent -= liability;
        i += 2; // skip the hash value of id
    }
    vec
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

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

fn generate_liabilities() -> Vec<u64> {
    let rng = &mut test_rng();

    let usernames: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    let liabilities: Vec<u64> = usernames.iter()
        .map(|_| { rng.gen_range(0..2_u64.pow(15)) })
        .collect();
    println!("{:?}", liabilities);

    let total: u64 = liabilities.iter().copied().sum();
    println!("total: {}", total);

    let mut vectors = Vec::<u64>::new();

    for (username, liability) in usernames.into_iter().zip(liabilities.into_iter()).rev() {
        let id = calculate_hash(&username);
        vectors.push(liability);
        vectors.push(id);
    }

    vectors.push(total);
    vectors.reverse();
    vectors
}

fn build_up_bits(value: u64, max_bits: usize) -> Vec<u64> {
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

#[cfg(test)]
fn compare_vecs(va: &[u64], vb: &[u64]) -> bool {
    (va.len() == vb.len()) &&
     va.iter()
       .zip(vb)
       .all(|(a,b)| *a == *b)
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
fn test_compute_aux_vector() {
    let total = vec![80];
    let first = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 5, 10, 20, 60];
    let second = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 6, 12, 25, 50, 10];
    let third = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 5, 10, 0];
    let vec = [total, first, second, third].concat();

    let liabilities = vec![80, 20, 50, 10];
    let aux_vec = compute_aux_vector(liabilities, 15);
    assert!(compare_vecs(&aux_vec, &vec));
}
