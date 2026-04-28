use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "pextrq",
        instruction: "vpextrq rax, xmm0, 1",
        architecture: Architecture::AMD64,
        bytes: &[0xc4, 0xe3, 0xf9, 0x16, 0xc0, 0x01],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pextrq",
        instruction: "pextrq rax, xmm0, 1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x48, 0x0f, 0x3a, 0x16, 0xc0, 0x01],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn pextrq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
