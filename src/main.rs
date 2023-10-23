use ark_ec::pairing::Pairing;
use ark_bls12_381::Bls12_381;
use ark_poly::Radix2EvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::KZG10;
use ark_std::test_rng;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use ark_bls12_381::Fr as F;
use solvency::common::calculate_hash;
use solvency::prover::data_structures::Prover;
use solvency::verifier::Verifier;
use solvency::verkle_tree::tree::VerkleNode;

#[allow(non_camel_case_types)]
type UniPoly_381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;

type D = Radix2EvaluationDomain::<F>;

fn main() {
    const MAX_BITS: usize = 16;

    let rng = &mut test_rng();

    let u1 = "ABCDEFG".chars().collect();
    let u2 = "HIJKLMNOPQ".chars().collect();
    let u3 = "RSTUVWXYZ".chars().collect();

    let l1 = generate_liabilities(u1);
    let l2 = generate_liabilities(u2);
    let l3 = generate_liabilities(u3);

    let number_of_liabilities = l1.len() + l2.len() + l3.len();
    let max_degree = ((number_of_liabilities - 1) / 2 * MAX_BITS + 1).checked_next_power_of_two().expect("");
    let pcs = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).expect("Setup failed");

    let group1 = VerkleNode::from(&pcs, l1.clone(), None, MAX_BITS).expect("");
    let group2 = VerkleNode::from(&pcs, l2.clone(), None, MAX_BITS).expect("");
    let group3 = VerkleNode::from(&pcs, l3.clone(), None, MAX_BITS).expect("");

    let groups = [[group1.clone()], [group2]].concat();
    let intermediate = VerkleNode::from(&pcs, [].to_vec(), Some(groups), MAX_BITS).expect("");
    let root = VerkleNode::from(&pcs, [].to_vec(), Some([[intermediate.clone()], [group3]].concat()), MAX_BITS).expect("");
    assert_eq!(root.value, l1[0] + l2[0] + l3[0]);

    let epsilon = F::rand(rng);
    let final_proof = Prover::generate_grand_proof(&root, epsilon);
    let username = 'A';
    let user_id = calculate_hash(&username);
    let proof = final_proof.get(&user_id).expect("UserId not found");
    Verifier::verify(proof, &pcs, user_id, l1[2]);
}

fn generate_liabilities(usernames: Vec<char>) -> Vec<u64> {
    let rng = &mut test_rng();

    let liabilities: Vec<u64> = usernames.iter()
        .map(|_| { rng.gen_range(0..2_u64.pow(10)) })
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
