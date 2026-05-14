use crate::ir::mir::Mir;
use crate::ir::mir::analysis::mir_successors;
use std::collections::HashSet;

pub fn reverse_post_order(mir: &Mir) -> Vec<String> {
    let successors = mir_successors(mir);
    let Some(entry) = mir.blocks().first().map(|block| block.name.clone()) else {
        return Vec::new();
    };
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    visit(&entry, &successors, &mut visited, &mut order);
    order.reverse();
    order
}

fn visit(
    block: &str,
    successors: &std::collections::HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    order: &mut Vec<String>,
) {
    if !visited.insert(block.to_string()) {
        return;
    }
    if let Some(edges) = successors.get(block) {
        for successor in edges {
            visit(successor, successors, visited, order);
        }
    }
    order.push(block.to_string());
}
