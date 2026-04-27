use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pshufw_semantics_stay_complete() {
    assert_complete_semantics(
        "pshufw mm0, mm1, 0x1b",
        Architecture::AMD64,
        &[0x0f, 0x70, 0xc1, 0x1b],
    );
}
