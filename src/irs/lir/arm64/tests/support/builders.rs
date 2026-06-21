use crate::irs::lir::{LirInstruction, LirStatus};

pub(crate) fn assert_lir_status(
    name: &str,
    bytes: &[u8],
    expected_status: LirStatus,
) -> LirInstruction {
    super::common::assert_lir_status(name, bytes, expected_status)
}
