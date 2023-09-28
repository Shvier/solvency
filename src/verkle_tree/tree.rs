use ark_poly::univariate::DensePolynomial;
use ark_bls12_381::Fr as F;

#[derive(Clone)]
pub enum NodeKind {
    Poly(DensePolynomial<F>),
    Balance,
}

#[derive(Clone)]
pub struct VerkleNode {
    pub id: usize,
    pub value: u64,
    pub kind: NodeKind,
    pub children: Option<Vec<VerkleNode>>,
}

impl VerkleNode {
    pub fn new(
        id: usize,
        value: u64, 
        kind: NodeKind, 
        children: Option<Vec<VerkleNode>>
    ) -> VerkleNode {
        VerkleNode { id: id, value: value, kind: kind, children: children }
    }
}
