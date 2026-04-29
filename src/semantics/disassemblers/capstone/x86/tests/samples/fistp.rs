use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "fistp",
        instruction: "fistp word ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xdf, 0x18],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fistp",
        instruction: "fistp dword ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xdb, 0x18],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fistp",
        instruction: "fistp qword ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xdf, 0x38],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn fistp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
