use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "vmaskmovps",
        instruction: "vmaskmovps xmm0, xmm1, xmmword ptr [rax]",
        architecture: Architecture::AMD64,
        bytes: &[0xc4, 0xe2, 0x71, 0x2c, 0x00],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "vmaskmovps",
        instruction: "vmaskmovps xmmword ptr [rax], xmm1, xmm2",
        architecture: Architecture::AMD64,
        bytes: &[0xc4, 0xe2, 0x71, 0x2e, 0x10],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn vmaskmov_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
