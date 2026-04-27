use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fchs_semantics_stay_complete() {
    assert_complete_semantics("fchs", Architecture::I386, &[0xd9, 0xe0]);
}
