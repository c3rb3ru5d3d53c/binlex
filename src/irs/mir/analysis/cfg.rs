use crate::irs::mir::{Mir, MirControlTarget, MirTerminator};
use std::collections::{HashMap, HashSet};

pub fn mir_successors(mir: &Mir) -> HashMap<String, Vec<String>> {
    let mut successors = HashMap::new();
    for block in mir.blocks() {
        let edges = match block.terminator.as_ref() {
            Some(MirTerminator::Jump { target, .. }) => direct_successors(target),
            Some(MirTerminator::CondBr {
                then_target,
                else_target,
                ..
            }) => {
                let mut edges = direct_successors(then_target);
                edges.extend(direct_successors(else_target));
                edges
            }
            _ => Vec::new(),
        };
        successors.insert(block.name.clone(), edges);
    }
    successors
}

fn direct_successors(target: &MirControlTarget) -> Vec<String> {
    match target {
        MirControlTarget::Direct(name) => vec![name.clone()],
        MirControlTarget::FunctionIndirect(_) | MirControlTarget::BlockIndirect(_) => Vec::new(),
    }
}

pub fn mir_predecessors(mir: &Mir) -> HashMap<String, Vec<String>> {
    let mut predecessors = HashMap::<String, Vec<String>>::new();
    for block in mir.blocks() {
        predecessors.entry(block.name.clone()).or_default();
    }
    for (source, targets) in mir_successors(mir) {
        for target in targets {
            predecessors.entry(target).or_default().push(source.clone());
        }
    }
    predecessors
}

pub fn reachable_blocks(mir: &Mir) -> HashSet<String> {
    let successors = mir_successors(mir);
    let Some(entry) = mir.blocks().first().map(|block| block.name.clone()) else {
        return HashSet::new();
    };
    let mut reachable = HashSet::new();
    visit(&entry, &successors, &mut reachable);
    reachable
}

fn visit(block: &str, successors: &HashMap<String, Vec<String>>, reachable: &mut HashSet<String>) {
    if !reachable.insert(block.to_string()) {
        return;
    }
    if let Some(edges) = successors.get(block) {
        for successor in edges {
            visit(successor, successors, reachable);
        }
    }
}
