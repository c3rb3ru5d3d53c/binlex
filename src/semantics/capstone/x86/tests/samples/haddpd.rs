use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "haddpd",
        instruction: "haddpd xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x7c, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "haddpd",
        instruction: "vhaddpd xmm0, xmm1, xmm2",
        architecture: Architecture::AMD64,
        bytes: &[0xc5, 0xf1, 0x7c, 0xc2],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn haddpd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
