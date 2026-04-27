use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
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
            (
                "fimul word ptr [rax]",
                Architecture::AMD64,
                vec![0xde, 0x08],
            ),
        ];

        for (name, architecture, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "system",
                instruction: name,
                architecture: architecture,
                bytes: (&bytes).to_vec(),
                expected_status: Some(SemanticStatus::Complete),
                semantics_fixture: None,
                roundtrip_fixture: None,
            });
        }
    }
    samples
}

fn conformance_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let i386_cases = [
            (
                "clc",
                vec![0xf8],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: (1 << 1) | (1 << 0),
                    memory: vec![],
                },
            ),
            (
                "stc",
                vec![0xf9],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "cmc",
                vec![0xf5],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: (1 << 1) | (1 << 0),
                    memory: vec![],
                },
            ),
            (
                "cld",
                vec![0xfc],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: (1 << 1) | (1 << 10),
                    memory: vec![],
                },
            ),
            (
                "std",
                vec![0xfd],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "lahf",
                vec![0x9f],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0)],
                    eflags: (1 << 1) | (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7),
                    memory: vec![],
                },
            ),
            (
                "sahf",
                vec![0x9e],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0x0000_d500)],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "cli",
                vec![0xfa],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: (1 << 1) | (1 << 9),
                    memory: vec![],
                },
            ),
            (
                "sti",
                vec![0xfb],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "pause",
                vec![0xf3, 0x90],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "wait",
                vec![0x9b],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "endbr32",
                vec![0xf3, 0x0f, 0x1e, 0xfb],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
        ];

        for (name, bytes, fixture) in i386_cases {
            samples.push(X86RuntimeSample {
                mnemonic: "system",
                instruction: name,
                architecture: Architecture::I386,
                bytes: (&bytes).to_vec(),
                expected_status: None,
                semantics_fixture: Some(fixture),
                roundtrip_fixture: None,
            });
        }

        let amd64_cases = [
            (
                "prefetchnta byte ptr [rax]",
                vec![0x0f, 0x18, 0x00],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0x3000)],
                    eflags: 1 << 1,
                    memory: vec![(0x3000, vec![0])],
                },
            ),
            (
                "prefetcht0 byte ptr [rax]",
                vec![0x0f, 0x18, 0x08],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0x3000)],
                    eflags: 1 << 1,
                    memory: vec![(0x3000, vec![0])],
                },
            ),
            (
                "prefetcht1 byte ptr [rax]",
                vec![0x0f, 0x18, 0x10],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0x3000)],
                    eflags: 1 << 1,
                    memory: vec![(0x3000, vec![0])],
                },
            ),
            (
                "prefetcht2 byte ptr [rax]",
                vec![0x0f, 0x18, 0x18],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0x3000)],
                    eflags: 1 << 1,
                    memory: vec![(0x3000, vec![0])],
                },
            ),
            (
                "prefetchw byte ptr [rax]",
                vec![0x0f, 0x0d, 0x08],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0x3000)],
                    eflags: 1 << 1,
                    memory: vec![(0x3000, vec![0])],
                },
            ),
            (
                "endbr64",
                vec![0xf3, 0x0f, 0x1e, 0xfa],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "lfence",
                vec![0x0f, 0xae, 0xe8],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "mfence",
                vec![0x0f, 0xae, 0xf0],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "sfence",
                vec![0x0f, 0xae, 0xf8],
                X86RuntimeFixtureSpec {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
            ),
            (
                "clflush byte ptr [rax]",
                vec![0x0f, 0xae, 0x38],
                X86RuntimeFixtureSpec {
                    registers: vec![(I386Register::Eax, 0x3000)],
                    eflags: 1 << 1,
                    memory: vec![(0x3000, vec![0])],
                },
            ),
        ];

        for (name, bytes, fixture) in amd64_cases {
            samples.push(X86RuntimeSample {
                mnemonic: "system",
                instruction: name,
                architecture: Architecture::AMD64,
                bytes: (&bytes).to_vec(),
                expected_status: None,
                semantics_fixture: Some(fixture),
                roundtrip_fixture: None,
            });
        }
    }
    samples
}

#[test]
fn system_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn system_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}
