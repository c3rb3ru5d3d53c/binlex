use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics,
    assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn system_semantics_stay_complete() {
    let cases = [
        ("clc", Architecture::AMD64, vec![0xf8]),
        ("stc", Architecture::AMD64, vec![0xf9]),
        ("cmc", Architecture::AMD64, vec![0xf5]),
        ("cld", Architecture::AMD64, vec![0xfc]),
        ("std", Architecture::AMD64, vec![0xfd]),
        ("lahf", Architecture::AMD64, vec![0x9f]),
        ("sahf", Architecture::AMD64, vec![0x9e]),
        ("sti", Architecture::AMD64, vec![0xfb]),
        ("cli", Architecture::AMD64, vec![0xfa]),
        ("pushfq", Architecture::AMD64, vec![0x9c]),
        ("popfq", Architecture::AMD64, vec![0x9d]),
        ("pushfd", Architecture::I386, vec![0x9c]),
        ("popfd", Architecture::I386, vec![0x9d]),
        ("pause", Architecture::I386, vec![0xf3, 0x90]),
        (
            "prefetchnta byte ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0x18, 0x00],
        ),
        (
            "prefetcht0 byte ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0x18, 0x08],
        ),
        (
            "prefetcht1 byte ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0x18, 0x10],
        ),
        (
            "prefetcht2 byte ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0x18, 0x18],
        ),
        (
            "prefetchw byte ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0x0d, 0x08],
        ),
        ("endbr32", Architecture::I386, vec![0xf3, 0x0f, 0x1e, 0xfb]),
        ("endbr64", Architecture::AMD64, vec![0xf3, 0x0f, 0x1e, 0xfa]),
        ("wait", Architecture::I386, vec![0x9b]),
        ("verr ax", Architecture::I386, vec![0x0f, 0x00, 0xe0]),
        ("verw ax", Architecture::I386, vec![0x0f, 0x00, 0xe8]),
        ("lfence", Architecture::AMD64, vec![0x0f, 0xae, 0xe8]),
        ("mfence", Architecture::AMD64, vec![0x0f, 0xae, 0xf0]),
        ("sfence", Architecture::AMD64, vec![0x0f, 0xae, 0xf8]),
        (
            "clflush byte ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0xae, 0x38],
        ),
        ("clts", Architecture::AMD64, vec![0x0f, 0x06]),
        ("invd", Architecture::AMD64, vec![0x0f, 0x08]),
        (
            "invlpg byte ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0x01, 0x38],
        ),
        ("wbinvd", Architecture::AMD64, vec![0x0f, 0x09]),
        ("cpuid", Architecture::AMD64, vec![0x0f, 0xa2]),
        (
            "ldmxcsr dword ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0xae, 0x10],
        ),
        (
            "stmxcsr dword ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0xae, 0x18],
        ),
        ("fxsave [rax]", Architecture::AMD64, vec![0x0f, 0xae, 0x00]),
        (
            "fxsave64 [rax]",
            Architecture::AMD64,
            vec![0x48, 0x0f, 0xae, 0x00],
        ),
        ("fxrstor [rax]", Architecture::AMD64, vec![0x0f, 0xae, 0x08]),
        (
            "fxrstor64 [rax]",
            Architecture::AMD64,
            vec![0x48, 0x0f, 0xae, 0x08],
        ),
        ("insd", Architecture::AMD64, vec![0x6d]),
        ("outsd", Architecture::AMD64, vec![0x6f]),
        ("rdtsc", Architecture::AMD64, vec![0x0f, 0x31]),
        ("rdtscp", Architecture::AMD64, vec![0x0f, 0x01, 0xf9]),
        ("sysenter", Architecture::AMD64, vec![0x0f, 0x34]),
        ("rdrand eax", Architecture::AMD64, vec![0x0f, 0xc7, 0xf0]),
        ("rdseed eax", Architecture::AMD64, vec![0x0f, 0xc7, 0xf8]),
        ("fimul word ptr [rax]", Architecture::AMD64, vec![0xde, 0x08]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn system_semantics_match_unicorn_transitions() {
    let i386_cases = [
        (
            "clc",
            vec![0xf8],
            I386Fixture {
                registers: vec![],
                eflags: (1 << 1) | (1 << 0),
                memory: vec![],
            },
        ),
        (
            "stc",
            vec![0xf9],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "cmc",
            vec![0xf5],
            I386Fixture {
                registers: vec![],
                eflags: (1 << 1) | (1 << 0),
                memory: vec![],
            },
        ),
        (
            "cld",
            vec![0xfc],
            I386Fixture {
                registers: vec![],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![],
            },
        ),
        (
            "std",
            vec![0xfd],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "lahf",
            vec![0x9f],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0)],
                eflags: (1 << 1) | (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7),
                memory: vec![],
            },
        ),
        (
            "sahf",
            vec![0x9e],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x0000_d500)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "cli",
            vec![0xfa],
            I386Fixture {
                registers: vec![],
                eflags: (1 << 1) | (1 << 9),
                memory: vec![],
            },
        ),
        (
            "sti",
            vec![0xfb],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pushfd",
            vec![0x9c],
            I386Fixture {
                registers: vec![(I386Register::Esp, 0x2800)],
                eflags: (1 << 1) | (1 << 0) | (1 << 2) | (1 << 9) | (1 << 10),
                memory: vec![],
            },
        ),
        (
            "popfd",
            vec![0x9d],
            I386Fixture {
                registers: vec![(I386Register::Esp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![(0x2800, vec![0x35, 0x06, 0x00, 0x00])],
            },
        ),
        (
            "pause",
            vec![0xf3, 0x90],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "wait",
            vec![0x9b],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "endbr32",
            vec![0xf3, 0x0f, 0x1e, 0xfb],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in i386_cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }

    let amd64_cases = [
        (
            "pushfq",
            vec![0x9c],
            I386Fixture {
                registers: vec![(I386Register::Rsp, 0x2800)],
                eflags: (1 << 1) | (1 << 0) | (1 << 2) | (1 << 9) | (1 << 10),
                memory: vec![],
            },
        ),
        (
            "popfq",
            vec![0x9d],
            I386Fixture {
                registers: vec![(I386Register::Rsp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![(0x2800, vec![0x35, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
            },
        ),
        (
            "prefetchnta byte ptr [rax]",
            vec![0x0f, 0x18, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x3000)],
                eflags: 1 << 1,
                memory: vec![(0x3000, vec![0])],
            },
        ),
        (
            "prefetcht0 byte ptr [rax]",
            vec![0x0f, 0x18, 0x08],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x3000)],
                eflags: 1 << 1,
                memory: vec![(0x3000, vec![0])],
            },
        ),
        (
            "prefetcht1 byte ptr [rax]",
            vec![0x0f, 0x18, 0x10],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x3000)],
                eflags: 1 << 1,
                memory: vec![(0x3000, vec![0])],
            },
        ),
        (
            "prefetcht2 byte ptr [rax]",
            vec![0x0f, 0x18, 0x18],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x3000)],
                eflags: 1 << 1,
                memory: vec![(0x3000, vec![0])],
            },
        ),
        (
            "prefetchw byte ptr [rax]",
            vec![0x0f, 0x0d, 0x08],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x3000)],
                eflags: 1 << 1,
                memory: vec![(0x3000, vec![0])],
            },
        ),
        (
            "endbr64",
            vec![0xf3, 0x0f, 0x1e, 0xfa],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "lfence",
            vec![0x0f, 0xae, 0xe8],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "mfence",
            vec![0x0f, 0xae, 0xf0],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "sfence",
            vec![0x0f, 0xae, 0xf8],
            I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "clflush byte ptr [rax]",
            vec![0x0f, 0xae, 0x38],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x3000)],
                eflags: 1 << 1,
                memory: vec![(0x3000, vec![0])],
            },
        ),
    ];

    for (name, bytes, fixture) in amd64_cases {
        assert_amd64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
