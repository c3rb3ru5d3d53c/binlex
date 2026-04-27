use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movntps_semantics_stay_complete() {
    assert_complete_semantics(
        "movntps xmmword ptr [rax], xmm0",
        Architecture::AMD64,
        &[0x0f, 0x2b, 0x00],
    );
}
