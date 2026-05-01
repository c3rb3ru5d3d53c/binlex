use crate::semantics::SemanticTerminator;
use crate::symbolic::{Error, Executor, State};

impl Executor {
    pub(crate) fn apply_terminator(
        &self,
        mut state: State,
        instruction: Option<&crate::semantics::InstructionEncoding>,
        terminator: &SemanticTerminator,
    ) -> Result<Vec<State>, Error> {
        match terminator {
            SemanticTerminator::FallThrough => Ok(vec![state]),
            SemanticTerminator::Jump { target } => {
                let target = self.eval_expression(&mut state, target, false)?;
                let target = self.concretize_if_dependency_free(&state, target)?;
                let target_value = self.coerce_address(&mut state, &target.value)?;
                let def_id = state.define_location(
                    instruction,
                    "program_counter".to_string(),
                    &target_value,
                    &target.deps,
                );
                state.set_program_counter(target_value, def_id);
                Ok(vec![state])
            }
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                let condition = self.eval_condition(&mut state, condition)?;
                let true_target = self.eval_expression(&mut state, true_target, false)?;
                let true_target = self.concretize_if_dependency_free(&state, true_target)?;
                let false_target = self.eval_expression(&mut state, false_target, false)?;
                let false_target = self.concretize_if_dependency_free(&state, false_target)?;
                let true_target_value = self.coerce_address(&mut state, &true_target.value)?;
                let false_target_value = self.coerce_address(&mut state, &false_target.value)?;

                let mut taken = state.clone();
                taken.add_constraint(condition.value.clone());
                let mut taken_parents = condition.deps.clone();
                taken_parents.extend(true_target.deps.clone());
                let taken_def_id = taken.define_location(
                    instruction,
                    "program_counter".to_string(),
                    &true_target_value,
                    &taken_parents,
                );
                taken.set_program_counter(true_target_value, taken_def_id);

                let mut not_taken = state;
                not_taken.add_constraint(condition.value.not());
                let mut not_taken_parents = condition.deps;
                not_taken_parents.extend(false_target.deps);
                let not_taken_def_id = not_taken.define_location(
                    instruction,
                    "program_counter".to_string(),
                    &false_target_value,
                    &not_taken_parents,
                );
                not_taken.set_program_counter(false_target_value, not_taken_def_id);

                Ok(vec![taken, not_taken])
            }
            SemanticTerminator::Return { expression } => {
                if let Some(expression) = expression {
                    let target = self.eval_expression(&mut state, expression, false)?;
                    let target = self.concretize_if_dependency_free(&state, target)?;
                    let target_value = self.coerce_address(&mut state, &target.value)?;
                    let def_id = state.define_location(
                        instruction,
                        "program_counter".to_string(),
                        &target_value,
                        &target.deps,
                    );
                    state.set_program_counter(target_value, def_id);
                }
                Ok(vec![state])
            }
            SemanticTerminator::Trap | SemanticTerminator::Unreachable => Ok(Vec::new()),
            SemanticTerminator::Call { target, .. } => {
                let target = self.eval_expression(&mut state, target, false)?;
                let target = self.concretize_if_dependency_free(&state, target)?;
                let target_value = self.coerce_address(&mut state, &target.value)?;
                let def_id = state.define_location(
                    instruction,
                    "program_counter".to_string(),
                    &target_value,
                    &target.deps,
                );
                state.set_program_counter(target_value, def_id);
                Ok(vec![state])
            }
        }
    }
}
