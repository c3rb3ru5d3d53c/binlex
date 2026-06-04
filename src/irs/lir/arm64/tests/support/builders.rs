use crate::irs::lir::{Lir, LirStatus};

pub(crate) fn assert_semantics_status(name: &str, bytes: &[u8], expected_status: LirStatus) -> Lir {
    super::common::assert_semantics_status(name, bytes, expected_status)
}
