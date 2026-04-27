use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn psraw_semantics_stay_complete() {
    assert_complete_semantics(
        "psraw xmm0, 1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x71, 0xe0, 0x01],
    );
}
