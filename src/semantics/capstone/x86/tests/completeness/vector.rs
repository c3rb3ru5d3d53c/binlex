use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn vector_and_scalar_fp_semantics_regressions_stay_complete() {
    let cases = [
        (
            "movsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x10, 0xc1],
        ),
        (
            "vmovsd xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xeb, 0x10, 0xc1],
        ),
        (
            "movss xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0x10, 0xc1],
        ),
        (
            "movss xmm0, dword ptr [rax]",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0x10, 0x00],
        ),
        (
            "movapd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x28, 0xc1],
        ),
        (
            "movdq2q mm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0xd6, 0xc1],
        ),
        (
            "movq2dq xmm0, mm1",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0xd6, 0xc1],
        ),
        (
            "movntdq xmmword ptr [rax], xmm0",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xe7, 0x00],
        ),
        (
            "movntpd xmmword ptr [rax], xmm0",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x2b, 0x00],
        ),
        (
            "movntps xmmword ptr [rax], xmm0",
            Architecture::AMD64,
            vec![0x0f, 0x2b, 0x00],
        ),
        (
            "movntq qword ptr [rax], mm0",
            Architecture::AMD64,
            vec![0x0f, 0xe7, 0x00],
        ),
        (
            "movnti dword ptr [rax], eax",
            Architecture::AMD64,
            vec![0x0f, 0xc3, 0x00],
        ),
        (
            "vmovntdq xmmword ptr [rax], xmm0",
            Architecture::AMD64,
            vec![0xc5, 0xf9, 0xe7, 0x00],
        ),
        (
            "movupd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x10, 0xc1],
        ),
        (
            "lddqu xmm0, xmmword ptr [rax]",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0xf0, 0x00],
        ),
        (
            "movddup xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x12, 0xc1],
        ),
        (
            "movshdup xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0x16, 0xc1],
        ),
        (
            "movsldup xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0x12, 0xc1],
        ),
        (
            "addsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x58, 0xc1],
        ),
        (
            "subsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x5c, 0xc1],
        ),
        (
            "mulsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x59, 0xc1],
        ),
        (
            "divsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x5e, 0xc1],
        ),
        (
            "minsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x5d, 0xc1],
        ),
        (
            "comisd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x2f, 0xc1],
        ),
        (
            "ucomisd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x2e, 0xc1],
        ),
        (
            "cvttsd2si eax, xmm0",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x2c, 0xc0],
        ),
        (
            "cvtdq2pd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0xe6, 0xc1],
        ),
        (
            "andps xmm0, xmm1",
            Architecture::AMD64,
            vec![0x0f, 0x54, 0xc1],
        ),
        (
            "andpd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x54, 0xc1],
        ),
        (
            "andnpd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x55, 0xc1],
        ),
        (
            "andnps xmm0, xmm1",
            Architecture::AMD64,
            vec![0x0f, 0x55, 0xc1],
        ),
        (
            "vpandn xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0xdf, 0xc1],
        ),
        (
            "pandn xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xdf, 0xc1],
        ),
        (
            "paddb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xfc, 0xc1],
        ),
        (
            "paddw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xfd, 0xc1],
        ),
        (
            "paddq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xd4, 0xc1],
        ),
        (
            "pavgb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xe0, 0xc1],
        ),
        (
            "vpaddb xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0xfc, 0xc1],
        ),
        (
            "pavgw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xe3, 0xc1],
        ),
        (
            "psubb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xf8, 0xc1],
        ),
        (
            "psubw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xf9, 0xc1],
        ),
        (
            "psubq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xfb, 0xc1],
        ),
        (
            "psllw xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x71, 0xf0, 0x01],
        ),
        (
            "psllq xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x73, 0xf0, 0x01],
        ),
        (
            "psraw xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x71, 0xe0, 0x01],
        ),
        (
            "psrlw xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x71, 0xd0, 0x01],
        ),
        (
            "psrlq xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x73, 0xd0, 0x01],
        ),
        (
            "pcmpeqb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x74, 0xc1],
        ),
        (
            "pcmpeqw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x75, 0xc1],
        ),
        (
            "pcmpeqd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x76, 0xc1],
        ),
        (
            "pcmpgtb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x64, 0xc1],
        ),
        (
            "pcmpgtw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x65, 0xc1],
        ),
        (
            "pcmpgtd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x66, 0xc1],
        ),
        (
            "pmaxsb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x3c, 0xc1],
        ),
        (
            "pmaxsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x3d, 0xc1],
        ),
        (
            "pmaxsw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xee, 0xc1],
        ),
        (
            "pmaxub xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xde, 0xc1],
        ),
        (
            "pmaxud xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x3f, 0xc1],
        ),
        (
            "pmaxuw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x3e, 0xc1],
        ),
        (
            "pminsb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x38, 0xc1],
        ),
        (
            "pminsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x39, 0xc1],
        ),
        (
            "pminsw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xea, 0xc1],
        ),
        (
            "pminub xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xda, 0xc1],
        ),
        (
            "pminud xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x3b, 0xc1],
        ),
        (
            "pminuw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x3a, 0xc1],
        ),
        (
            "pmaddwd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xf5, 0xc1],
        ),
        (
            "vpmaddwd xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0xf5, 0xc1],
        ),
        (
            "vpackssdw xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0x6b, 0xc1],
        ),
        (
            "vpacksswb xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0x63, 0xc1],
        ),
        (
            "vpackuswb xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0x67, 0xc1],
        ),
        (
            "pmulhw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xe5, 0xc1],
        ),
        (
            "vpmulhw xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0xe5, 0xc1],
        ),
        (
            "pmulld xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x40, 0xc1],
        ),
        (
            "pmullw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xd5, 0xc1],
        ),
        (
            "pmuludq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xf4, 0xc1],
        ),
        (
            "packssdw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x6b, 0xc1],
        ),
        (
            "packsswb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x63, 0xc1],
        ),
        (
            "packuswb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x67, 0xc1],
        ),
        (
            "palignr xmm0, xmm1, 8",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x3a, 0x0f, 0xc1, 0x08],
        ),
        (
            "punpckhbw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x68, 0xc1],
        ),
        (
            "punpcklwd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x61, 0xc1],
        ),
        (
            "punpckhwd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x69, 0xc1],
        ),
        (
            "punpckldq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x62, 0xc1],
        ),
        (
            "punpckhdq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x6a, 0xc1],
        ),
        (
            "punpcklqdq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x6c, 0xc1],
        ),
        (
            "punpckhqdq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x6d, 0xc1],
        ),
        (
            "unpckhpd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x15, 0xc1],
        ),
        (
            "unpcklps xmm0, xmm1",
            Architecture::AMD64,
            vec![0x0f, 0x14, 0xc1],
        ),
        (
            "unpckhps xmm0, xmm1",
            Architecture::AMD64,
            vec![0x0f, 0x15, 0xc1],
        ),
        (
            "unpcklpd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x14, 0xc1],
        ),
        (
            "pextrb eax, xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x3a, 0x14, 0xc0, 0x01],
        ),
        (
            "vpextrb eax, xmm0, 1",
            Architecture::AMD64,
            vec![0xc4, 0xe3, 0x79, 0x14, 0xc0, 0x01],
        ),
        (
            "pextrd eax, xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x3a, 0x16, 0xc0, 0x01],
        ),
        (
            "vpextrd eax, xmm0, 1",
            Architecture::AMD64,
            vec![0xc4, 0xe3, 0x79, 0x16, 0xc0, 0x01],
        ),
        (
            "vpextrq rax, xmm0, 1",
            Architecture::AMD64,
            vec![0xc4, 0xe3, 0xf9, 0x16, 0xc0, 0x01],
        ),
        (
            "vpextrw eax, xmm0, 1",
            Architecture::AMD64,
            vec![0xc5, 0xf9, 0xc5, 0xc0, 0x01],
        ),
        (
            "pinsrb xmm0, eax, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x3a, 0x20, 0xc0, 0x01],
        ),
        (
            "pinsrd xmm0, eax, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x3a, 0x22, 0xc0, 0x01],
        ),
        (
            "movmskps eax, xmm0",
            Architecture::AMD64,
            vec![0x0f, 0x50, 0xc0],
        ),
        (
            "movmskpd eax, xmm0",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x50, 0xc0],
        ),
        (
            "pmovmskb eax, xmm0",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xd7, 0xc0],
        ),
        (
            "vpmovmskb eax, xmm0",
            Architecture::AMD64,
            vec![0xc5, 0xf9, 0xd7, 0xc0],
        ),
        (
            "vextracti128 xmm0, ymm1, 1",
            Architecture::AMD64,
            vec![0xc4, 0xe3, 0x7d, 0x39, 0xc8, 0x01],
        ),
        (
            "vperm2i128 ymm0, ymm2, ymm1, 0x31",
            Architecture::AMD64,
            vec![0xc4, 0xe3, 0x6d, 0x46, 0xc1, 0x31],
        ),
        (
            "vpermq ymm0, ymm1, 0x1b",
            Architecture::AMD64,
            vec![0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b],
        ),
        (
            "vpbroadcastb xmm0, xmm1",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x79, 0x78, 0xc1],
        ),
        (
            "vpsignw xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x69, 0x09, 0xc1],
        ),
        (
            "ptest xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x17, 0xc1],
        ),
        (
            "vptest xmm0, xmm1",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x79, 0x17, 0xc1],
        ),
        (
            "vpcmpeqq xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc4, 0xe2, 0x69, 0x29, 0xc1],
        ),
        (
            "vpminub xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0xda, 0xc1],
        ),
        (
            "movhlps xmm0, xmm1",
            Architecture::AMD64,
            vec![0x0f, 0x12, 0xc1],
        ),
        (
            "movlhps xmm0, xmm1",
            Architecture::AMD64,
            vec![0x0f, 0x16, 0xc1],
        ),
        (
            "movhpd xmm0, qword ptr [rax]",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x16, 0x00],
        ),
        (
            "movlpd xmm0, qword ptr [rax]",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x12, 0x00],
        ),
        (
            "movhps xmm0, qword ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0x16, 0x00],
        ),
        (
            "movlps xmm0, qword ptr [rax]",
            Architecture::AMD64,
            vec![0x0f, 0x12, 0x00],
        ),
        (
            "pshufb xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x00, 0xc1],
        ),
        (
            "vpshufd xmm0, xmm1, 0x1b",
            Architecture::AMD64,
            vec![0xc5, 0xf9, 0x70, 0xc1, 0x1b],
        ),
        (
            "vpunpckhwd xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0x69, 0xc1],
        ),
        (
            "pmovsxbw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x20, 0xc1],
        ),
        (
            "pmovsxbd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x21, 0xc1],
        ),
        (
            "pmovsxbq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x22, 0xc1],
        ),
        (
            "pmovsxwd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x23, 0xc1],
        ),
        (
            "pmovsxwq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x24, 0xc1],
        ),
        (
            "pmovsxdq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x25, 0xc1],
        ),
        (
            "pmovzxbw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x30, 0xc1],
        ),
        (
            "pmovzxbd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x31, 0xc1],
        ),
        (
            "pmovzxbq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x32, 0xc1],
        ),
        (
            "pmovzxwd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x33, 0xc1],
        ),
        (
            "pmovzxwq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x34, 0xc1],
        ),
        (
            "pmovzxdq xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x38, 0x35, 0xc1],
        ),
        (
            "pshufd xmm0, xmm1, 0x1b",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x70, 0xc1, 0x1b],
        ),
        (
            "pshufhw xmm0, xmm1, 0x1b",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0x70, 0xc1, 0x1b],
        ),
        (
            "pshuflw xmm0, xmm1, 0x1b",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x70, 0xc1, 0x1b],
        ),
        (
            "pshufw mm0, mm1, 0x1b",
            Architecture::AMD64,
            vec![0x0f, 0x70, 0xc1, 0x1b],
        ),
        (
            "pextrw eax, xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xc5, 0xc0, 0x01],
        ),
        (
            "pextrq rax, xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x48, 0x0f, 0x3a, 0x16, 0xc0, 0x01],
        ),
        (
            "pinsrq xmm0, rax, 1",
            Architecture::AMD64,
            vec![0x66, 0x48, 0x0f, 0x3a, 0x22, 0xc0, 0x01],
        ),
        (
            "extractps eax, xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x3a, 0x17, 0xc0, 0x01],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
