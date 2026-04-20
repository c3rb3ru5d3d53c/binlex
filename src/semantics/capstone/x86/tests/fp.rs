use super::common::assert_complete_semantics;
use crate::Architecture;

#[test]
fn x87_semantics_regressions_stay_complete() {
    let cases = [
        ("fld dword ptr [eax]", Architecture::I386, vec![0xd9, 0x00]),
        ("fld1", Architecture::I386, vec![0xd9, 0xe8]),
        ("fldz", Architecture::I386, vec![0xd9, 0xee]),
        ("fild dword ptr [eax]", Architecture::I386, vec![0xdb, 0x00]),
        ("fst dword ptr [eax]", Architecture::I386, vec![0xd9, 0x10]),
        ("fstp dword ptr [eax]", Architecture::I386, vec![0xd9, 0x18]),
        ("fadd dword ptr [eax]", Architecture::I386, vec![0xd8, 0x00]),
        ("faddp st(1)", Architecture::I386, vec![0xde, 0xc1]),
        ("fmul dword ptr [eax]", Architecture::I386, vec![0xd8, 0x08]),
        ("fmulp st(1)", Architecture::I386, vec![0xde, 0xc9]),
        (
            "fsubr dword ptr [eax]",
            Architecture::I386,
            vec![0xd8, 0x28],
        ),
        ("fsub dword ptr [eax]", Architecture::I386, vec![0xd8, 0x20]),
        ("fsubp st(1)", Architecture::I386, vec![0xde, 0xe9]),
        ("fsubrp st(1)", Architecture::I386, vec![0xde, 0xe1]),
        ("fdiv dword ptr [eax]", Architecture::I386, vec![0xd8, 0x30]),
        (
            "fdivr dword ptr [eax]",
            Architecture::I386,
            vec![0xd8, 0x38],
        ),
        ("fdivrp st(1)", Architecture::I386, vec![0xde, 0xf1]),
        (
            "fcomp dword ptr [eax]",
            Architecture::I386,
            vec![0xd8, 0x18],
        ),
        ("fcom dword ptr [eax]", Architecture::I386, vec![0xd8, 0x10]),
        ("fcompp", Architecture::I386, vec![0xde, 0xd9]),
        ("fucom st(1)", Architecture::I386, vec![0xdd, 0xe1]),
        ("fucomp st(1)", Architecture::I386, vec![0xdd, 0xe9]),
        ("fnstsw ax", Architecture::I386, vec![0xdf, 0xe0]),
        ("fabs", Architecture::I386, vec![0xd9, 0xe1]),
        ("fchs", Architecture::I386, vec![0xd9, 0xe0]),
        ("fxch st(1)", Architecture::I386, vec![0xd9, 0xc9]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
