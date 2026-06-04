use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "addsubpd",
        instruction: "addsubpd xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0xd0, 0xc1],
        expected_status: Some(LirStatus::Complete),
        lir_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "addsubpd",
        instruction: "vaddsubpd xmm0, xmm1, xmm2",
        architecture: Architecture::AMD64,
        bytes: &[0xc5, 0xf1, 0xd0, 0xc2],
        expected_status: Some(LirStatus::Complete),
        lir_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn addsubpd_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
