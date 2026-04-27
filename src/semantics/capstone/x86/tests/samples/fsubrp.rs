use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fsubrp_semantics_stay_complete() {
    assert_complete_semantics("fsubrp st(1)", Architecture::I386, &[0xde, 0xe1]);
}
