use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fucomp_semantics_stay_complete() {
    assert_complete_semantics("fucomp st(1)", Architecture::I386, &[0xdd, 0xe9]);
}
