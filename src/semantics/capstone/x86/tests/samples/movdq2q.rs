use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movdq2q_semantics_stay_complete() {
    assert_complete_semantics(
        "movdq2q mm0, xmm1",
        Architecture::AMD64,
        &[0xf2, 0x0f, 0xd6, 0xc1],
    );
}
