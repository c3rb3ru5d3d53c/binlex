use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movntpd_semantics_stay_complete() {
    assert_complete_semantics(
        "movntpd xmmword ptr [rax], xmm0",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x2b, 0x00],
    );
}
