use crate::irs::hir::HirFunction;

pub fn optimize(function: &mut HirFunction) {
    function.optimize_inline_temps();
    function.optimize_algebraic();
    function.optimize_condition_idioms();
    function.optimize_boolean();
    function.optimize_load_hoisting();
    function.optimize_call_arguments();
    function.optimize_memory_forms();
    function.optimize_pointer_reads();
    function.optimize_cfg();
    function.optimize_undefs();
    function.optimize_inline_temps();
    function.optimize_undefs();
    function.optimize_algebraic();
    function.optimize_condition_idioms();
    function.optimize_boolean();
    function.optimize_locals();
}
