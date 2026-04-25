use crate::semantics::InstructionSemantics;

pub(crate) fn assert_complete_semantics(name: &str, bytes: &[u8]) -> InstructionSemantics {
    super::common::assert_complete_semantics(name, bytes)
}
