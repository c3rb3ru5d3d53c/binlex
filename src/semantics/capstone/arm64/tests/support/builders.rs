use crate::semantics::{InstructionSemantics, SemanticStatus};

pub(crate) fn assert_semantics_status(
    name: &str,
    bytes: &[u8],
    expected_status: SemanticStatus,
) -> InstructionSemantics {
    super::common::assert_semantics_status(name, bytes, expected_status)
}
