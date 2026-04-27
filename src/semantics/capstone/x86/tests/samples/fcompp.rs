use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fcompp_semantics_stay_complete() {
    assert_complete_semantics("fcompp", Architecture::I386, &[0xde, 0xd9]);
}
