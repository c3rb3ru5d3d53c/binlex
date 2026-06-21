use super::LoweringContext;
use crate::irs::lir::LirExpression;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn const_return_adjust(expression: &LirExpression) -> Option<u16> {
        match expression {
            LirExpression::Const { value, .. } => u16::try_from(*value).ok(),
            _ => None,
        }
    }
}
