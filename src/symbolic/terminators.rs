use crate::semantics::SemanticTerminator;
use crate::symbolic::{Error, Executor, State};

impl Executor {
    pub(crate) fn apply_terminator(
        &self,
        mut state: State,
        terminator: &SemanticTerminator,
    ) -> Result<Vec<State>, Error> {
        match terminator {
            SemanticTerminator::FallThrough => Ok(vec![state]),
            SemanticTerminator::Jump { target } => {
                let target = self.eval_expression(&mut state, target, false)?;
                let target = self.coerce_address(&mut state, &target)?;
                state.set_program_counter(target);
                Ok(vec![state])
            }
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                let condition = self.eval_condition(&mut state, condition)?;
                let true_target = self.eval_expression(&mut state, true_target, false)?;
                let false_target = self.eval_expression(&mut state, false_target, false)?;
                let true_target = self.coerce_address(&mut state, &true_target)?;
                let false_target = self.coerce_address(&mut state, &false_target)?;

                let mut taken = state.clone();
                taken.add_constraint(condition.clone());
                taken.set_program_counter(true_target);

                let mut not_taken = state;
                not_taken.add_constraint(condition.not());
                not_taken.set_program_counter(false_target);

                Ok(vec![taken, not_taken])
            }
            SemanticTerminator::Return { expression } => {
                if let Some(expression) = expression {
                    let target = self.eval_expression(&mut state, expression, false)?;
                    let target = self.coerce_address(&mut state, &target)?;
                    state.set_program_counter(target);
                }
                Ok(vec![state])
            }
            SemanticTerminator::Trap | SemanticTerminator::Unreachable => Ok(Vec::new()),
            SemanticTerminator::Call { target, .. } => {
                let target = self.eval_expression(&mut state, target, false)?;
                let target = self.coerce_address(&mut state, &target)?;
                state.set_program_counter(target);
                Ok(vec![state])
            }
        }
    }
}
