use super::memory_state::optimize_memory_state;
use crate::ir::mir::Mir;

pub fn optimize_memory_aliases(mir: &mut Mir) {
    optimize_memory_state(mir);
}
