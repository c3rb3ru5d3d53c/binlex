use crate::Architecture;
use crate::controlflow::{Graph, InstructionRecord};
use crate::semantics::{Semantic, SemanticCpu, SemanticTerminator};
use crate::symbolic::{SymbolicCpuState, SymbolicExecutor};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpaquePredicateResolution {
    Taken { target: u64 },
    Fallthrough { target: u64 },
}

pub fn resolve_single_block_opaque_predicate(
    architecture: Architecture,
    block_start: u64,
    terminator: &InstructionRecord,
    cfg: &Graph,
) -> Option<OpaquePredicateResolution> {
    if !cfg.config.semantics.enabled {
        return None;
    }
    if !terminator.is_jump || !terminator.is_conditional || terminator.has_indirect_target {
        return None;
    }

    let branch_target = terminator.to.iter().next().copied()?;
    if terminator.to.len() != 1 {
        return None;
    }
    let fallthrough_target = terminator.fallthrough()?;

    let semantics = block_semantics(block_start, terminator.address, cfg)?;
    if !matches!(
        semantics.last().map(|item| &item.terminator),
        Some(SemanticTerminator::Branch { .. })
    ) {
        return None;
    }

    let cpu = SemanticCpu::from_architecture(architecture).ok()?;
    let initial_state = SymbolicCpuState::new(cpu);
    let executor = SymbolicExecutor::new();
    let final_states = executor.run(semantics.iter(), &initial_state, None).ok()?;

    let mut feasible_targets = BTreeSet::new();
    for state in final_states {
        let program_counter = state.program_counter().ok().flatten()?;
        if program_counter == branch_target || program_counter == fallthrough_target {
            feasible_targets.insert(program_counter);
        } else {
            return None;
        }
    }

    if feasible_targets.len() != 1 {
        return None;
    }

    let target = feasible_targets.into_iter().next()?;
    if target == branch_target {
        Some(OpaquePredicateResolution::Taken { target })
    } else if target == fallthrough_target {
        Some(OpaquePredicateResolution::Fallthrough { target })
    } else {
        None
    }
}

fn block_semantics(block_start: u64, terminator_address: u64, cfg: &Graph) -> Option<Vec<Semantic>> {
    let mut result = Vec::new();
    for entry in cfg.listing.range(block_start..) {
        let instruction = entry.value();
        result.push(instruction.semantics.clone()?);
        if !matches!(instruction.semantics.as_ref()?.status, crate::semantics::SemanticStatus::Complete) {
            return None;
        }
        if instruction.address == terminator_address {
            return Some(result);
        }
        if instruction.address > terminator_address {
            return None;
        }
    }
    None
}
