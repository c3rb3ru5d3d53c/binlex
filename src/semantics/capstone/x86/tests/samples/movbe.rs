use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "movbe",
        instruction: "movbe eax, dword ptr [eax]",
        architecture: Architecture::I386,
        bytes: &[0x0f, 0x38, 0xf0, 0x00],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "movbe",
        instruction: "movbe dword ptr [eax], ebx",
        architecture: Architecture::I386,
        bytes: &[0x0f, 0x38, 0xf1, 0x18],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn movbe_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
