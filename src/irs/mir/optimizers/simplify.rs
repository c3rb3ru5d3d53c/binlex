use crate::irs::mir::Mir;
use std::time::{Duration, Instant};

pub fn optimize(mir: &mut Mir) {
    mir.optimize_blocks();
    mir.optimize_abi();
    mir.optimize_stack_slots();
    mir.optimize_returns();
    mir.optimize_calls();
    mir.optimize_stack();
    mir.optimize_stack_pointers();
    mir.optimize_call_clobbers();
    mir.optimize_register_state();
    mir.optimize_flags();
    mir.optimize_undefs();
    mir.optimize_subexpressions();
    mir.optimize_intrinsics();
    mir.optimize_flags();
    mir.optimize_stack_slots();
    mir.optimize_stack_pointers();
    mir.optimize_memory_state();
    mir.optimize_branches();
    mir.optimize_ssa();
    mir.optimize_ssa_liveness();
    mir.optimize_constants();
    mir.optimize_copy_propagation();
    mir.optimize_cse();
    mir.optimize_memory_aliases();
    mir.optimize_memory_state();
    mir.optimize_targets();
    mir.optimize_liveness();
    mir.optimize_dead_effects();
    mir.optimize_branches();
    mir.optimize_targets();
    mir.optimize_ssa_liveness();
    mir.optimize_blocks();
    mir.optimize_targets();
    mir.optimize_stack();
    mir.optimize_stack_pointers();
    mir.optimize_abi();
    mir.optimize_flags();
    mir.optimize_dead_effects();
}

pub(crate) fn optimize_with_timing<F>(mir: &mut Mir, mut record: F)
where
    F: FnMut(&'static str, Duration),
{
    macro_rules! pass {
        ($name:literal, $call:expr) => {{
            let started_at = Instant::now();
            $call;
            record($name, started_at.elapsed());
        }};
    }

    pass!("blocks_1", mir.optimize_blocks());
    pass!("abi_1", mir.optimize_abi());
    pass!("stack_slots_1", mir.optimize_stack_slots());
    pass!("returns", mir.optimize_returns());
    pass!("calls", mir.optimize_calls());
    pass!("stack_1", mir.optimize_stack());
    pass!("stack_pointers_1", mir.optimize_stack_pointers());
    pass!("call_clobbers", mir.optimize_call_clobbers());
    pass!("register_state", mir.optimize_register_state());
    pass!("flags_1", mir.optimize_flags());
    pass!("undefs", mir.optimize_undefs());
    pass!("subexpressions", mir.optimize_subexpressions());
    pass!("intrinsics", mir.optimize_intrinsics());
    pass!("flags_2", mir.optimize_flags());
    pass!("stack_slots_2", mir.optimize_stack_slots());
    pass!("stack_pointers_2", mir.optimize_stack_pointers());
    pass!("memory_state_1", mir.optimize_memory_state());
    pass!("branches_1", mir.optimize_branches());
    pass!("ssa", mir.optimize_ssa());
    pass!("ssa_liveness_1", mir.optimize_ssa_liveness());
    pass!("constants", mir.optimize_constants());
    pass!("copy_propagation", mir.optimize_copy_propagation());
    pass!("cse", mir.optimize_cse());
    pass!("memory_aliases", mir.optimize_memory_aliases());
    pass!("memory_state_2", mir.optimize_memory_state());
    pass!("targets_1", mir.optimize_targets());
    pass!("liveness", mir.optimize_liveness());
    pass!("dead_effects_1", mir.optimize_dead_effects());
    pass!("branches_2", mir.optimize_branches());
    pass!("targets_2", mir.optimize_targets());
    pass!("ssa_liveness_2", mir.optimize_ssa_liveness());
    pass!("blocks_2", mir.optimize_blocks());
    pass!("targets_3", mir.optimize_targets());
    pass!("stack_2", mir.optimize_stack());
    pass!("stack_pointers_3", mir.optimize_stack_pointers());
    pass!("abi_2", mir.optimize_abi());
    pass!("flags_3", mir.optimize_flags());
    pass!("dead_effects_2", mir.optimize_dead_effects());
}
