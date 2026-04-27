use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn vpbroadcastb_semantics_stay_complete() {
    assert_complete_semantics(
        "vpbroadcastb xmm0, xmm1",
        Architecture::AMD64,
        &[0xc4, 0xe2, 0x79, 0x78, 0xc1],
    );
}
