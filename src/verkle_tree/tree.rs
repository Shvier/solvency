use std::fmt;

use ark_ec::bls12::Bls12;
use ark_poly::univariate::DensePolynomial;
use ark_bls12_381::{Fr as F, Bls12_381};
use ark_poly_commit::kzg10::{Commitment, Proof};
use ark_ff::FftField;

use crate::error::Error;

#[derive(Clone, Debug, PartialEq)]
pub struct NodePolyProofPair {
    pub witness_p: Proof<Bls12_381>,
    pub proof_z: Option<(Commitment<Bls12_381>, Proof<Bls12_381>)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodePolyProof {
    pub p: DensePolynomial<F>,
    pub com_p: Commitment<Bls12_381>,
    pub w1: DensePolynomial<F>,
    pub w2: DensePolynomial<F>,
    pub w3: DensePolynomial<F>,
    pub proofs: Vec<NodePolyProofPair>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum NodeKind {
    Poly(
        NodePolyProof,
    ),
    Balance,
    UserId,
    ComHash
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
       match self {
            NodeKind::Poly(_) => write!(f, "Poly"),
            NodeKind::Balance => write!(f, "Balance"),
            NodeKind::UserId => write!(f, "UserId"),
            NodeKind::ComHash => write!(f, "ComHash"),
       }
    }
}

#[derive(Clone, Debug)]
pub struct VerkleNode {
    pub id: u64, // user id or hash of commitment
    pub idx: usize, // idx in the vector commitment
    pub value: u64, // liability
    pub kind: NodeKind,
    pub children: Option<Vec<VerkleNode>>,
}

impl VerkleNode {
    pub fn new(
        id: u64,
        idx: usize,
        value: u64, 
        kind: NodeKind, 
        children: Option<Vec<VerkleNode>>
    ) -> VerkleNode {
        VerkleNode { 
            id: id,
            idx: idx, 
            value: value, 
            kind: kind, 
            children: children 
        }
    }

    pub fn to_id_node(&self) -> Result<ProofIdNode, Error> {
        match &self.kind {
            NodeKind::ComHash | NodeKind::Balance | NodeKind::UserId => {
                let node = ProofIdNode {
                    id: self.id,
                    idx: self.idx,
                };
                Ok(node)
            }
            _ => {
                Err(Error::InvalidNodeType)
            }
        }
    }

    pub fn trim(&self) -> Result<ProofValueNode, Error> {
        match &self.kind {
            NodeKind::Poly(poly) => {
                let proofs = &poly.proofs;
                let len = poly.p.coeffs.len().checked_next_power_of_two().expect("");
                let omega = F::get_root_of_unity(len as u64).unwrap();
                let node = ProofValueNode {
                    id: self.id,
                    idx: self.idx,
                    kind: ProofValueNodeKind::Poly(ProofValuleNodePoly {
                        omega,
                        com_p: poly.com_p,
                        proofs: proofs.to_vec(),
                    }),
                };
                Ok(node)
            }
            NodeKind::Balance => {
                let node = ProofValueNode {
                    id: self.id,
                    idx: self.idx,
                    kind: ProofValueNodeKind::Balance,
                };
                Ok(node)
            }
            _ => {
                Err(Error::InvalidNodeType)
            }
        }
    }
}

#[derive(Clone)]
pub struct ProofIdNode {
    pub id: u64,
    pub idx: usize,
}

#[derive(Clone)]
pub struct ProofValuleNodePoly {
    pub omega: F,
    pub com_p: Commitment<Bls12_381>,
    pub proofs: Vec<NodePolyProofPair>,
}

#[derive(Clone)]
pub enum ProofValueNodeKind {
    Balance,
    Poly(ProofValuleNodePoly),
}

#[derive(Clone)]
pub struct ProofValueNode {
    pub id: u64, 
    pub idx: usize,
    pub kind: ProofValueNodeKind,
}
