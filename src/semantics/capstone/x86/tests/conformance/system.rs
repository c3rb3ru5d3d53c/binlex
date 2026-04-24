use super::super::support::{
    I386Fixture, I386Register, assert_amd64_semantics_match_unicorn,
    assert_i386_semantics_match_unicorn,
};

#[test]
fn system_semantics_match_unicorn_transitions() {
    let cases = [
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

    for (name, bytes, fixture) in cases {
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
