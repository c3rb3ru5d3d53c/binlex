use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "pextrb",
        instruction: "pextrb eax, xmm0, 1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x3a, 0x14, 0xc0, 0x01],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pextrb",
        instruction: "vpextrb eax, xmm0, 1",
        architecture: Architecture::AMD64,
        bytes: &[0xc4, 0xe3, 0x79, 0x14, 0xc0, 0x01],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn pextrb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
