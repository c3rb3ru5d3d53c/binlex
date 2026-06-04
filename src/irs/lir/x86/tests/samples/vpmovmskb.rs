use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpmovmskb",
    instruction: "vpmovmskb eax, xmm0",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf9, 0xd7, 0xc0],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpmovmskb_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
