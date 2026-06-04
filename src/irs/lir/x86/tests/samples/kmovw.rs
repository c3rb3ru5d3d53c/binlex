use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "kmovw",
    instruction: "kmovw k1, k2",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf8, 0x90, 0xca],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn kmovw_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
