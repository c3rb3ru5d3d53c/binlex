use super::subexpressions::optimize_subexpressions;
use crate::irs::mir::Mir;

pub fn optimize_cse(mir: &mut Mir) {
    optimize_subexpressions(mir);
}
