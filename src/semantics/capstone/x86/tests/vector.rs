use super::common::{
    I386Fixture, I386Register, WideI386Fixture, assert_amd64_semantics_match_unicorn,
    assert_complete_semantics, interpret_amd64_wide_semantics,
};
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
            "vmovdqa xmm0, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xf9, 0x6f, 0xc1],
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
            "por xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xeb, 0xc1],
        ),
        (
            "pand xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xdb, 0xc1],
        ),
        (
            "pandn xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xdf, 0xc1],
        ),
        (
            "pxor xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xef, 0xc1],
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
            "paddd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xfe, 0xc1],
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
            "psubd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xfa, 0xc1],
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
            "pslld xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x72, 0xf0, 0x01],
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
            "psrad xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x72, 0xe0, 0x01],
        ),
        (
            "psrlw xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x71, 0xd0, 0x01],
        ),
        (
            "psrld xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x72, 0xd0, 0x01],
        ),
        (
            "psrlq xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x73, 0xd0, 0x01],
        ),
        (
            "pslldq xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x73, 0xf8, 0x01],
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
            "punpcklbw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x60, 0xc1],
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
            "vpslldq xmm0, xmm1, 1",
            Architecture::AMD64,
            vec![0xc5, 0xf9, 0x73, 0xf9, 0x01],
        ),
        (
            "vpsrldq xmm0, xmm1, 1",
            Architecture::AMD64,
            vec![0xc5, 0xf9, 0x73, 0xd9, 0x01],
        ),
        (
            "vpunpcklbw xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0x60, 0xc1],
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

fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

fn vec256(low: [u8; 16], high: [u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&low);
    bytes.extend_from_slice(&high);
    bytes
}

#[test]
fn vector_integer_and_move_semantics_match_unicorn_transitions() {
    let xmm0 = vec128([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
        0x22,
    ]);
    let xmm1 = vec128([
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99,
        0x88,
    ]);
    let mask = vec128([
        0x00, 0x81, 0x02, 0x83, 0x04, 0x85, 0x06, 0x87, 0x08, 0x89, 0x0a, 0x8b, 0x0c, 0x8d, 0x0e,
        0x8f,
    ]);
    let mem128 = vec![
        0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57, 0x9b,
        0xdf,
    ];

    let cases = [
        (
            "movapd xmm0, xmm1",
            vec![0x66, 0x0f, 0x28, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movntdq xmmword ptr [rax], xmm0",
            vec![0x66, 0x0f, 0xe7, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![(0x3000, vec![0; 16])],
            },
        ),
        (
            "lddqu xmm0, xmmword ptr [rax]",
            vec![0xf2, 0x0f, 0xf0, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, 0)],
                eflags: 1 << 1,
                memory: vec![(0x3000, mem128.clone())],
            },
        ),
        (
            "movddup xmm0, xmm1",
            vec![0xf2, 0x0f, 0x12, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movshdup xmm0, xmm1",
            vec![0xf3, 0x0f, 0x16, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movsldup xmm0, xmm1",
            vec![0xf3, 0x0f, 0x12, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "andpd xmm0, xmm1",
            vec![0x66, 0x0f, 0x54, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "andnps xmm0, xmm1",
            vec![0x0f, 0x55, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "por xmm0, xmm1",
            vec![0x66, 0x0f, 0xeb, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pandn xmm0, xmm1",
            vec![0x66, 0x0f, 0xdf, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "paddb xmm0, xmm1",
            vec![0x66, 0x0f, 0xfc, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "paddd xmm0, xmm1",
            vec![0x66, 0x0f, 0xfe, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pavgb xmm0, xmm1",
            vec![0x66, 0x0f, 0xe0, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "psubw xmm0, xmm1",
            vec![0x66, 0x0f, 0xf9, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "psllq xmm0, 1",
            vec![0x66, 0x0f, 0x73, 0xf0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "psrad xmm0, 1",
            vec![0x66, 0x0f, 0x72, 0xe0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "psrldq xmm0, 1",
            vec![0x66, 0x0f, 0x73, 0xd8, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pcmpeqb xmm0, xmm1",
            vec![0x66, 0x0f, 0x74, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pcmpgtw xmm0, xmm1",
            vec![0x66, 0x0f, 0x65, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmaxub xmm0, xmm1",
            vec![0x66, 0x0f, 0xde, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pminsw xmm0, xmm1",
            vec![0x66, 0x0f, 0xea, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmaddwd xmm0, xmm1",
            vec![0x66, 0x0f, 0xf5, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmulhw xmm0, xmm1",
            vec![0x66, 0x0f, 0xe5, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmuludq xmm0, xmm1",
            vec![0x66, 0x0f, 0xf4, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "packsswb xmm0, xmm1",
            vec![0x66, 0x0f, 0x63, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "punpcklbw xmm0, xmm1",
            vec![0x66, 0x0f, 0x60, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pextrd eax, xmm0, 1",
            vec![0x66, 0x0f, 0x3a, 0x16, 0xc0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pinsrd xmm0, eax, 1",
            vec![0x66, 0x0f, 0x3a, 0x22, 0xc0, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0x1234_5678), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmovmskb eax, xmm0",
            vec![0x66, 0x0f, 0xd7, 0xc0],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "ptest xmm0, xmm1",
            vec![0x66, 0x0f, 0x38, 0x17, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movhlps xmm0, xmm1",
            vec![0x0f, 0x12, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "movhpd xmm0, qword ptr [rax]",
            vec![0x66, 0x0f, 0x16, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![(0x3000, mem128[..8].to_vec())],
            },
        ),
        (
            "pshufb xmm0, xmm1",
            vec![0x66, 0x0f, 0x38, 0x00, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, mask)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmovsxbw xmm0, xmm1",
            vec![0x66, 0x0f, 0x38, 0x20, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pmovzxdq xmm0, xmm1",
            vec![0x66, 0x0f, 0x38, 0x35, 0xc1],
            I386Fixture {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_amd64_semantics_match_unicorn(name, &bytes, fixture);
    }
}

// Unicorn 2.1.5 rejects these AVX YMM forms with `INSN_INVALID`, so keep them
// as semantics-only wide regressions until a reliable execution oracle is
// available for 256-bit x86 vectors in this environment.
#[test]
fn vector_ymm_semantics_wide_regressions() {
    let ymm0 = vec256(
        [
            0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x11, 0x22,
        ],
        [
            0x01, 0x81, 0x02, 0x82, 0x03, 0x83, 0x04, 0x84, 0x05, 0x85, 0x06, 0x86, 0x07, 0x87,
            0x08, 0x88,
        ],
    );
    let ymm1 = vec256(
        [
            0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0x99, 0x88,
        ],
        [
            0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a, 0x96, 0x69,
            0x87, 0x78,
        ],
    );
    let ymm2 = vec256(
        [
            0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57,
            0x9b, 0xdf,
        ],
        [
            0x24, 0x42, 0x66, 0x81, 0xa5, 0xc3, 0xe7, 0xff, 0x18, 0x36, 0x54, 0x72, 0x90, 0xab,
            0xcd, 0xef,
        ],
    );

    let cases = [
        (
            "vextracti128 xmm0, ymm1, 1",
            vec![0xc4, 0xe3, 0x7d, 0x39, 0xc8, 0x01],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![(I386Register::Xmm0, 0)],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![(I386Register::Ymm1, ymm1.clone())],
            },
            Some((
                "reg_122",
                vec![
                    0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a, 0x96,
                    0x69, 0x87, 0x78,
                ],
            )),
            None,
        ),
        (
            "vperm2i128 ymm0, ymm2, ymm1, 0x31",
            vec![0xc4, 0xe3, 0x6d, 0x46, 0xc1, 0x31],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, vec![0; 32]),
                    (I386Register::Ymm1, ymm1.clone()),
                    (I386Register::Ymm2, ymm2.clone()),
                ],
            },
            Some((
                "reg_154",
                vec![
                    0x24, 0x42, 0x66, 0x81, 0xa5, 0xc3, 0xe7, 0xff, 0x18, 0x36, 0x54, 0x72, 0x90,
                    0xab, 0xcd, 0xef, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b,
                    0xa5, 0x5a, 0x96, 0x69, 0x87, 0x78,
                ],
            )),
            None,
        ),
        (
            "vpermq ymm0, ymm1, 0x1b",
            vec![0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, vec![0; 32]),
                    (I386Register::Ymm1, ymm1.clone()),
                ],
            },
            Some((
                "reg_154",
                vec![
                    0xb4, 0x4b, 0xa5, 0x5a, 0x96, 0x69, 0x87, 0x78, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2,
                    0x2d, 0xc3, 0x3c, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x01, 0xff,
                    0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc,
                ],
            )),
            None,
        ),
        (
            "vpshufd ymm0, ymm1, 0x1b",
            vec![0xc5, 0xfd, 0x70, 0xc1, 0x1b],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, vec![0; 32]),
                    (I386Register::Ymm1, ymm1.clone()),
                ],
            },
            Some((
                "reg_154",
                vec![
                    0x11, 0x00, 0x99, 0x88, 0x55, 0x44, 0x33, 0x22, 0x03, 0xfd, 0x04, 0xfc, 0x01,
                    0xff, 0x02, 0xfe, 0x96, 0x69, 0x87, 0x78, 0xb4, 0x4b, 0xa5, 0x5a, 0xd2, 0x2d,
                    0xc3, 0x3c, 0xf0, 0x0f, 0xe1, 0x1e,
                ],
            )),
            None,
        ),
        (
            "vptest ymm0, ymm1",
            vec![0xc4, 0xe2, 0x7d, 0x17, 0xc1],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, ymm0.clone()),
                    (I386Register::Ymm1, ymm1.clone()),
                ],
            },
            None,
            Some((false, false)),
        ),
        (
            "vpmovmskb eax, ymm0",
            vec![0xc5, 0xfd, 0xd7, 0xc0],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![(I386Register::Eax, 0)],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![(I386Register::Ymm0, ymm0.clone())],
            },
            Some(("reg_19", vec![0x02, 0x3f, 0xaa, 0xaa])),
            None,
        ),
        (
            "vpunpcklbw ymm0, ymm2, ymm1",
            vec![0xc5, 0xed, 0x60, 0xc1],
            WideI386Fixture {
                base: I386Fixture {
                    registers: vec![],
                    eflags: 1 << 1,
                    memory: vec![],
                },
                wide_registers: vec![
                    (I386Register::Ymm0, vec![0; 32]),
                    (I386Register::Ymm1, ymm1),
                    (I386Register::Ymm2, ymm2),
                ],
            },
            Some((
                "reg_154",
                vec![
                    0xde, 0x01, 0xad, 0xff, 0xbe, 0x02, 0xef, 0xfe, 0x10, 0x03, 0x32, 0xfd, 0x54,
                    0x04, 0x76, 0xfc, 0x24, 0xf0, 0x42, 0x0f, 0x66, 0xe1, 0x81, 0x1e, 0xa5, 0xd2,
                    0xc3, 0x2d, 0xe7, 0xc3, 0xff, 0x3c,
                ],
            )),
            None,
        ),
    ];

    for (name, bytes, fixture, expected_register, expected_flags) in cases {
        let (registers, flags) = interpret_amd64_wide_semantics(name, &bytes, fixture);
        if let Some((register, expected)) = expected_register {
            assert_eq!(
                registers.get(register).expect("register should exist"),
                &expected,
                "{name}: register {register} mismatch",
            );
        }
        if let Some((zf, cf)) = expected_flags {
            assert_eq!(flags.zf, zf, "{name}: zf mismatch");
            assert_eq!(flags.cf, cf, "{name}: cf mismatch");
        }
    }
}
