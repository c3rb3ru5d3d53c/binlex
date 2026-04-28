use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cvttsd2si",
    instruction: "cvttsd2si eax, xmm0",
    architecture: Architecture::AMD64,
    bytes: &[0xf2, 0x0f, 0x2c, 0xc0],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 0),
            (
                I386Register::Xmm0,
                0x1122_3344_5566_7788_4045_6000_0000_0000,
            ),
        ],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn cvttsd2si_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cvttsd2si_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
