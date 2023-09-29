use std::collections::HashMap;

use crate::verkle_tree::tree::*;

pub struct Verifier {

}

impl Verifier {
    pub fn verify(path: &HashMap<u64, Vec<u64>>, user_id: u64, balance: u64, root: &VerkleNode) {
        let mut path: Vec<u64>= path.get(&user_id).expect("UserId not found").clone();
        path.reverse();
        let nodes = Verifier::generate_nodes_from(path, &root);
        for (id_node, value_node) in nodes {
            println!("{} - {}", id_node.kind, value_node.kind);
        }
    }
}

impl Verifier {
    #[inline]
    fn generate_nodes_from(mut path: Vec<u64>, root: &VerkleNode) -> Vec<(VerkleNode, VerkleNode)> {
        if path.len() <= 0 {
            return [].to_vec();
        }
        let pos = path.pop().unwrap() as usize;
        let children = root.children.as_deref().expect("Root is empy");
        let value_node = &children[pos];
        let id_node = &children[pos - 1];
        let mut nodes = Vec::<(VerkleNode, VerkleNode)>::new();
        nodes.push((id_node.clone(), value_node.clone()));
        let other_nodes = Verifier::generate_nodes_from(path, value_node);
        nodes.extend(other_nodes);
        nodes
    }
}