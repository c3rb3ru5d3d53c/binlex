use super::{I386Register, X86FixtureSpec, X86Sample, assert_roundtrip_cases};
use crate::Architecture;

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "ror",
        instruction: "ror eax, 1",
        architecture: Architecture::I386,
        bytes: &[0xd1, 0xc8],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x8123_4567),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: &[],
        }),
    },
    X86Sample {
        mnemonic: "ror",
        instruction: "ror eax, cl",
        architecture: Architecture::I386,
        bytes: &[0xd3, 0xc8],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x8123_4567),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x0000_0003),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: &[],
        }),
    },
];

#[test]
fn ror_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
