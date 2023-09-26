use ark_poly::univariate::DensePolynomial;
use ark_bls12_381::Fr as F;

pub enum NodeKind {
    Poly(DensePolynomial<F>),
    Balance,
}

pub struct Node {
    pub value: u64,
    pub kind: NodeKind,
    pub children: Option<Vec<Node>>,
}

impl Node {
    pub fn new(value: u64, kind: NodeKind, children: Option<Vec<Node>>) -> Node {
        Node { value: value, kind: kind, children: children }
    }
}