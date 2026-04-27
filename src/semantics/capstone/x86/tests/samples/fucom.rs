use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fucom_semantics_stay_complete() {
    assert_complete_semantics("fucom st(1)", Architecture::I386, &[0xdd, 0xe1]);
}
