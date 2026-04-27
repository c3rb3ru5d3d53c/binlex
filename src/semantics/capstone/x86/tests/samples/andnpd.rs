use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn andnpd_semantics_stay_complete() {
    assert_complete_semantics(
        "andnpd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x55, 0xc1],
    );
}
