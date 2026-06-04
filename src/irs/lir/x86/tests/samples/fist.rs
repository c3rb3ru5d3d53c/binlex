use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "fist",
        instruction: "fist word ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xdf, 0x10],
        expected_status: Some(LirStatus::Complete),
        lir_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fist",
        instruction: "fist dword ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xdb, 0x10],
        expected_status: Some(LirStatus::Complete),
        lir_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn fist_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
