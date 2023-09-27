use ark_poly::univariate::DensePolynomial;
use ark_bls12_381::Fr as F;

pub enum NodeKind {
    Poly(DensePolynomial<F>),
    Balance,
}

impl Clone for NodeKind {
    fn clone(&self) -> Self {
        match self {
            Self::Poly(arg0) => Self::Poly(arg0.clone()),
            Self::Balance => Self::Balance,
        }
    }
}

pub struct VerkleNode {
    pub value: u64,
    pub kind: NodeKind,
    pub children: Option<Vec<VerkleNode>>,
}

impl VerkleNode {
    pub fn new(value: u64, kind: NodeKind, children: Option<Vec<VerkleNode>>) -> VerkleNode {
        VerkleNode { value: value, kind: kind, children: children }
    }
}

impl Clone for VerkleNode {
    fn clone(&self) -> Self {
        Self { value: self.value.clone(), kind: self.kind.clone(), children: self.children.clone() }
    }
}
