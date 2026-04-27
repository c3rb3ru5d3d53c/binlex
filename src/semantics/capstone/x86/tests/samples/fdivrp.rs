use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fdivrp_semantics_stay_complete() {
    assert_complete_semantics("fdivrp st(1)", Architecture::I386, &[0xde, 0xf1]);
}
