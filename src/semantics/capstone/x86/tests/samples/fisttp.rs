use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "fisttp",
        instruction: "fisttp word ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xdf, 0x08],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fisttp",
        instruction: "fisttp dword ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xdb, 0x08],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fisttp",
        instruction: "fisttp qword ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xdd, 0x08],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn fisttp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
