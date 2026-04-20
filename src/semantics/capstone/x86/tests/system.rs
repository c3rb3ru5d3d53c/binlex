use super::common::assert_complete_semantics;
use crate::Architecture;

#[test]
fn system_and_io_semantics_regressions_stay_complete() {
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
        assert_complete_semantics(name, architecture, &bytes);
    }
}
