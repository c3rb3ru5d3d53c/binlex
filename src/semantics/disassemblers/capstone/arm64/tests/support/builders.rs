use crate::semantics::{Semantic, SemanticStatus};

pub(crate) fn assert_semantics_status(
    name: &str,
    bytes: &[u8],
    expected_status: SemanticStatus,
) -> Semantic {
    super::common::assert_semantics_status(name, bytes, expected_status)
}
