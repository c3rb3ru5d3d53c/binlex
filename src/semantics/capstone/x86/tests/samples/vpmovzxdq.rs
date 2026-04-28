use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpmovzxdq",
    instruction: "vpmovzxdq xmm0, qword ptr [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x79, 0x35, 0x00],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpmovzxdq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
