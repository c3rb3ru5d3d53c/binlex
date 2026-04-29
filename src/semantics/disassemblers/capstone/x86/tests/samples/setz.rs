use super::{I386Register, X86FixtureSpec, X86Sample, assert_roundtrip_cases};
use crate::Architecture;

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "setz",
        instruction: "setz al",
        architecture: Architecture::I386,
        bytes: &[0x0f, 0x94, 0xc0],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: &[],
        }),
    },
    X86Sample {
        mnemonic: "setz",
        instruction: "setz al",
        architecture: Architecture::AMD64,
        bytes: &[0x0f, 0x94, 0xc0],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: &[],
        }),
    },
];

#[test]
fn setz_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
}
