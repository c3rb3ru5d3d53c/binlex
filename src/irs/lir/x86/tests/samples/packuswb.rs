use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "packuswb",
        instruction: "packuswb xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x67, 0xc1],
        expected_status: Some(LirStatus::Complete),
        lir_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "packuswb",
        instruction: "vpackuswb xmm0, xmm2, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0xc5, 0xe9, 0x67, 0xc1],
        expected_status: Some(LirStatus::Complete),
        lir_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn packuswb_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
