use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movmskpd_semantics_stay_complete() {
    assert_complete_semantics(
        "movmskpd eax, xmm0",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x50, 0xc0],
    );
}
