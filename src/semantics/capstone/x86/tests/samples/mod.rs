use std::collections::BTreeMap;

use super::support::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
    assert_amd64_semantics_match_unicorn, assert_i386_instruction_roundtrip_match_unicorn,
    assert_i386_semantics_match_unicorn, assert_semantics_status,
};
use crate::Architecture;
use crate::semantics::SemanticStatus;

#[derive(Clone, Copy, Debug)]
pub(crate) struct X86FixtureSpec {
    pub registers: &'static [(I386Register, u128)],
    pub eflags: u32,
    pub memory: &'static [(u64, &'static [u8])],
}

impl From<X86FixtureSpec> for I386Fixture {
    fn from(spec: X86FixtureSpec) -> Self {
        Self {
            registers: spec.registers.to_vec(),
            eflags: spec.eflags,
            memory: spec
                .memory
                .iter()
                .map(|(address, bytes)| (*address, bytes.to_vec()))
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct X86RuntimeFixtureSpec {
    pub registers: Vec<(I386Register, u128)>,
    pub eflags: u32,
    pub memory: Vec<(u64, Vec<u8>)>,
}

impl From<X86RuntimeFixtureSpec> for I386Fixture {
    fn from(spec: X86RuntimeFixtureSpec) -> Self {
        Self {
            registers: spec.registers,
            eflags: spec.eflags,
            memory: spec.memory,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct X86Sample {
    pub mnemonic: &'static str,
    pub instruction: &'static str,
    pub architecture: Architecture,
    pub bytes: &'static [u8],
    pub expected_status: Option<SemanticStatus>,
    pub semantics_fixture: Option<X86FixtureSpec>,
    pub roundtrip_fixture: Option<X86FixtureSpec>,
}

#[derive(Clone, Debug)]
pub(crate) struct X86RuntimeSample {
    pub mnemonic: &'static str,
    pub instruction: &'static str,
    pub architecture: Architecture,
    pub bytes: Vec<u8>,
    pub expected_status: Option<SemanticStatus>,
    pub semantics_fixture: Option<X86RuntimeFixtureSpec>,
    pub roundtrip_fixture: Option<X86RuntimeFixtureSpec>,
}

pub(crate) fn assert_sample_statuses(samples: &[X86Sample]) {
    for sample in samples {
        if let Some(expected_status) = sample.expected_status {
            let sample_name = format!(
                "{} {}: {}",
                sample.architecture, sample.mnemonic, sample.instruction
            );
            assert_semantics_status(
                &sample_name,
                sample.architecture,
                sample.bytes,
                expected_status,
            );
        }
    }
}

pub(crate) fn assert_runtime_sample_statuses(samples: &[X86RuntimeSample]) {
    for sample in samples {
        if let Some(expected_status) = sample.expected_status {
            let sample_name = format!(
                "{} {}: {}",
                sample.architecture, sample.mnemonic, sample.instruction
            );
            assert_semantics_status(
                &sample_name,
                sample.architecture,
                &sample.bytes,
                expected_status,
            );
        }
    }
}

pub(crate) fn assert_conformance_cases(samples: &[X86Sample]) {
    for sample in samples {
        if let Some(fixture) = sample.semantics_fixture {
            let sample_name = format!(
                "{} {}: {}",
                sample.architecture, sample.mnemonic, sample.instruction
            );
            match sample.architecture {
                Architecture::I386 => {
                    assert_i386_semantics_match_unicorn(&sample_name, sample.bytes, fixture.into())
                }
                Architecture::AMD64 => {
                    assert_amd64_semantics_match_unicorn(&sample_name, sample.bytes, fixture.into())
                }
                architecture => panic!("unsupported x86 sample architecture: {architecture}"),
            }
        }
    }
}

pub(crate) fn assert_runtime_conformance_cases(samples: &[X86RuntimeSample]) {
    for sample in samples {
        if let Some(fixture) = sample.semantics_fixture.clone() {
            let sample_name = format!(
                "{} {}: {}",
                sample.architecture, sample.mnemonic, sample.instruction
            );
            match sample.architecture {
                Architecture::I386 => {
                    assert_i386_semantics_match_unicorn(&sample_name, &sample.bytes, fixture.into())
                }
                Architecture::AMD64 => assert_amd64_semantics_match_unicorn(
                    &sample_name,
                    &sample.bytes,
                    fixture.into(),
                ),
                architecture => panic!("unsupported x86 sample architecture: {architecture}"),
            }
        }
    }
}

pub(crate) fn assert_roundtrip_cases(samples: &[X86Sample]) {
    for sample in samples {
        if let Some(fixture) = sample.roundtrip_fixture {
            let sample_name = format!(
                "{} {}: {}",
                sample.architecture, sample.mnemonic, sample.instruction
            );
            match sample.architecture {
                Architecture::I386 => assert_i386_instruction_roundtrip_match_unicorn(
                    &sample_name,
                    sample.bytes,
                    fixture.into(),
                ),
                Architecture::AMD64 => assert_amd64_instruction_roundtrip_match_unicorn(
                    &sample_name,
                    sample.bytes,
                    fixture.into(),
                ),
                architecture => panic!("unsupported x86 sample architecture: {architecture}"),
            }
        }
    }
}

pub(crate) fn assert_runtime_roundtrip_cases(samples: &[X86RuntimeSample]) {
    for sample in samples {
        if let Some(fixture) = sample.roundtrip_fixture.clone() {
            let sample_name = format!(
                "{} {}: {}",
                sample.architecture, sample.mnemonic, sample.instruction
            );
            match sample.architecture {
                Architecture::I386 => assert_i386_instruction_roundtrip_match_unicorn(
                    &sample_name,
                    &sample.bytes,
                    fixture.into(),
                ),
                Architecture::AMD64 => assert_amd64_instruction_roundtrip_match_unicorn(
                    &sample_name,
                    &sample.bytes,
                    fixture.into(),
                ),
                architecture => panic!("unsupported x86 sample architecture: {architecture}"),
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) fn sample_registry() -> BTreeMap<String, &'static [X86Sample]> {
    let mut samples = BTreeMap::new();
    samples.insert("aaa".to_string(), aaa::SAMPLES);
    samples.insert("aad".to_string(), aad::SAMPLES);
    samples.insert("aam".to_string(), aam::SAMPLES);
    samples.insert("aas".to_string(), aas::SAMPLES);
    samples.insert("adc".to_string(), adc::SAMPLES);
    samples.insert("adcx".to_string(), adcx::SAMPLES);
    samples.insert("add".to_string(), add::SAMPLES);
    samples.insert("andn".to_string(), andn::SAMPLES);
    samples.insert("andnpd".to_string(), andnpd::SAMPLES);
    samples.insert("andps".to_string(), andps::SAMPLES);
    samples.insert("blsi".to_string(), blsi::SAMPLES);
    samples.insert("blsmsk".to_string(), blsmsk::SAMPLES);
    samples.insert("blsr".to_string(), blsr::SAMPLES);
    samples.insert("bsf".to_string(), bsf::SAMPLES);
    samples.insert("bsr".to_string(), bsr::SAMPLES);
    samples.insert("bswap".to_string(), bswap::SAMPLES);
    samples.insert("bt".to_string(), bt::SAMPLES);
    samples.insert("btc".to_string(), btc::SAMPLES);
    samples.insert("btr".to_string(), btr::SAMPLES);
    samples.insert("bts".to_string(), bts::SAMPLES);
    samples.insert("bzhi".to_string(), bzhi::SAMPLES);
    samples.insert("cmovbe".to_string(), cmovbe::SAMPLES);
    samples.insert("cmovc".to_string(), cmovc::SAMPLES);
    samples.insert("cmovge".to_string(), cmovge::SAMPLES);
    samples.insert("cmovl".to_string(), cmovl::SAMPLES);
    samples.insert("cmovle".to_string(), cmovle::SAMPLES);
    samples.insert("cmovz".to_string(), cmovz::SAMPLES);
    samples.insert("cmp".to_string(), cmp::SAMPLES);
    samples.insert("cmpxchg".to_string(), cmpxchg::SAMPLES);
    samples.insert("cmpxchg16b".to_string(), cmpxchg16b::SAMPLES);
    samples.insert("cmpxchg8b".to_string(), cmpxchg8b::SAMPLES);
    samples.insert("cvttsd2si".to_string(), cvttsd2si::SAMPLES);
    samples.insert("dec".to_string(), dec::SAMPLES);
    samples.insert("div".to_string(), div::SAMPLES);
    samples.insert("extractps".to_string(), extractps::SAMPLES);
    samples.insert("fabs".to_string(), fabs::SAMPLES);
    samples.insert("fadd".to_string(), fadd::SAMPLES);
    samples.insert("faddp".to_string(), faddp::SAMPLES);
    samples.insert("fchs".to_string(), fchs::SAMPLES);
    samples.insert("fcom".to_string(), fcom::SAMPLES);
    samples.insert("fcomp".to_string(), fcomp::SAMPLES);
    samples.insert("fcompp".to_string(), fcompp::SAMPLES);
    samples.insert("fdiv".to_string(), fdiv::SAMPLES);
    samples.insert("fdivr".to_string(), fdivr::SAMPLES);
    samples.insert("fdivrp".to_string(), fdivrp::SAMPLES);
    samples.insert("fild".to_string(), fild::SAMPLES);
    samples.insert("fld".to_string(), fld::SAMPLES);
    samples.insert("fld1".to_string(), fld1::SAMPLES);
    samples.insert("fldz".to_string(), fldz::SAMPLES);
    samples.insert("fmul".to_string(), fmul::SAMPLES);
    samples.insert("fmulp".to_string(), fmulp::SAMPLES);
    samples.insert("fnstsw".to_string(), fnstsw::SAMPLES);
    samples.insert("fst".to_string(), fst::SAMPLES);
    samples.insert("fstp".to_string(), fstp::SAMPLES);
    samples.insert("fsub".to_string(), fsub::SAMPLES);
    samples.insert("fsubp".to_string(), fsubp::SAMPLES);
    samples.insert("fsubr".to_string(), fsubr::SAMPLES);
    samples.insert("fsubrp".to_string(), fsubrp::SAMPLES);
    samples.insert("fucom".to_string(), fucom::SAMPLES);
    samples.insert("fucomp".to_string(), fucomp::SAMPLES);
    samples.insert("fxch".to_string(), fxch::SAMPLES);
    samples.insert("idiv".to_string(), idiv::SAMPLES);
    samples.insert("inc".to_string(), inc::SAMPLES);
    samples.insert("leave".to_string(), leave::SAMPLES);
    samples.insert("lzcnt".to_string(), lzcnt::SAMPLES);
    samples.insert("movdq2q".to_string(), movdq2q::SAMPLES);
    samples.insert("movbe".to_string(), movbe::SAMPLES);
    samples.insert("movhps".to_string(), movhps::SAMPLES);
    samples.insert("movlhps".to_string(), movlhps::SAMPLES);
    samples.insert("movlpd".to_string(), movlpd::SAMPLES);
    samples.insert("movlps".to_string(), movlps::SAMPLES);
    samples.insert("movmskpd".to_string(), movmskpd::SAMPLES);
    samples.insert("movmskps".to_string(), movmskps::SAMPLES);
    samples.insert("movnti".to_string(), movnti::SAMPLES);
    samples.insert("movntpd".to_string(), movntpd::SAMPLES);
    samples.insert("movntps".to_string(), movntps::SAMPLES);
    samples.insert("movntq".to_string(), movntq::SAMPLES);
    samples.insert("movq2dq".to_string(), movq2dq::SAMPLES);
    samples.insert("movupd".to_string(), movupd::SAMPLES);
    samples.insert("mulx".to_string(), mulx::SAMPLES);
    samples.insert("neg".to_string(), neg::SAMPLES);
    samples.insert("not".to_string(), not::SAMPLES);
    samples.insert("paddq".to_string(), paddq::SAMPLES);
    samples.insert("paddw".to_string(), paddw::SAMPLES);
    samples.insert("palignr".to_string(), palignr::SAMPLES);
    samples.insert("pand".to_string(), pand::SAMPLES);
    samples.insert("pavgw".to_string(), pavgw::SAMPLES);
    samples.insert("pcmpeqd".to_string(), pcmpeqd::SAMPLES);
    samples.insert("pcmpeqq".to_string(), pcmpeqq::SAMPLES);
    samples.insert("pcmpeqw".to_string(), pcmpeqw::SAMPLES);
    samples.insert("pcmpgtb".to_string(), pcmpgtb::SAMPLES);
    samples.insert("pcmpgtd".to_string(), pcmpgtd::SAMPLES);
    samples.insert("pdep".to_string(), pdep::SAMPLES);
    samples.insert("pext".to_string(), pext::SAMPLES);
    samples.insert("pinsrb".to_string(), pinsrb::SAMPLES);
    samples.insert("pinsrq".to_string(), pinsrq::SAMPLES);
    samples.insert("pmaxsb".to_string(), pmaxsb::SAMPLES);
    samples.insert("pmaxsd".to_string(), pmaxsd::SAMPLES);
    samples.insert("pmaxsw".to_string(), pmaxsw::SAMPLES);
    samples.insert("pmaxud".to_string(), pmaxud::SAMPLES);
    samples.insert("pmaxuw".to_string(), pmaxuw::SAMPLES);
    samples.insert("pminsb".to_string(), pminsb::SAMPLES);
    samples.insert("pminsd".to_string(), pminsd::SAMPLES);
    samples.insert("pminud".to_string(), pminud::SAMPLES);
    samples.insert("pminuw".to_string(), pminuw::SAMPLES);
    samples.insert("pmovsxbd".to_string(), pmovsxbd::SAMPLES);
    samples.insert("pmovsxbq".to_string(), pmovsxbq::SAMPLES);
    samples.insert("pmovsxdq".to_string(), pmovsxdq::SAMPLES);
    samples.insert("pmovsxwd".to_string(), pmovsxwd::SAMPLES);
    samples.insert("pmovsxwq".to_string(), pmovsxwq::SAMPLES);
    samples.insert("pmovzxbd".to_string(), pmovzxbd::SAMPLES);
    samples.insert("pmovzxbq".to_string(), pmovzxbq::SAMPLES);
    samples.insert("pmovzxbw".to_string(), pmovzxbw::SAMPLES);
    samples.insert("pmovzxwd".to_string(), pmovzxwd::SAMPLES);
    samples.insert("pmovzxwq".to_string(), pmovzxwq::SAMPLES);
    samples.insert("pmulld".to_string(), pmulld::SAMPLES);
    samples.insert("pmullw".to_string(), pmullw::SAMPLES);
    samples.insert("popcnt".to_string(), popcnt::SAMPLES);
    samples.insert("pshufhw".to_string(), pshufhw::SAMPLES);
    samples.insert("pshuflw".to_string(), pshuflw::SAMPLES);
    samples.insert("pshufw".to_string(), pshufw::SAMPLES);
    samples.insert("pslld".to_string(), pslld::SAMPLES);
    samples.insert("psllw".to_string(), psllw::SAMPLES);
    samples.insert("psraw".to_string(), psraw::SAMPLES);
    samples.insert("psrld".to_string(), psrld::SAMPLES);
    samples.insert("psrlq".to_string(), psrlq::SAMPLES);
    samples.insert("psrlw".to_string(), psrlw::SAMPLES);
    samples.insert("psubb".to_string(), psubb::SAMPLES);
    samples.insert("psubd".to_string(), psubd::SAMPLES);
    samples.insert("psubq".to_string(), psubq::SAMPLES);
    samples.insert("punpckhbw".to_string(), punpckhbw::SAMPLES);
    samples.insert("punpckhdq".to_string(), punpckhdq::SAMPLES);
    samples.insert("punpckhqdq".to_string(), punpckhqdq::SAMPLES);
    samples.insert("punpckldq".to_string(), punpckldq::SAMPLES);
    samples.insert("punpcklqdq".to_string(), punpcklqdq::SAMPLES);
    samples.insert("punpcklwd".to_string(), punpcklwd::SAMPLES);
    samples.insert("ret".to_string(), ret::SAMPLES);
    samples.insert("rol".to_string(), rol::SAMPLES);
    samples.insert("ror".to_string(), ror::SAMPLES);
    samples.insert("rorx".to_string(), rorx::SAMPLES);
    samples.insert("sarx".to_string(), sarx::SAMPLES);
    samples.insert("setbe".to_string(), setbe::SAMPLES);
    samples.insert("setc".to_string(), setc::SAMPLES);
    samples.insert("setg".to_string(), setg::SAMPLES);
    samples.insert("setge".to_string(), setge::SAMPLES);
    samples.insert("setl".to_string(), setl::SAMPLES);
    samples.insert("setle".to_string(), setle::SAMPLES);
    samples.insert("setnz".to_string(), setnz::SAMPLES);
    samples.insert("seto".to_string(), seto::SAMPLES);
    samples.insert("sets".to_string(), sets::SAMPLES);
    samples.insert("setz".to_string(), setz::SAMPLES);
    samples.insert("shl".to_string(), shl::SAMPLES);
    samples.insert("shld".to_string(), shld::SAMPLES);
    samples.insert("shlx".to_string(), shlx::SAMPLES);
    samples.insert("shrd".to_string(), shrd::SAMPLES);
    samples.insert("shrx".to_string(), shrx::SAMPLES);
    samples.insert("sub".to_string(), sub::SAMPLES);
    samples.insert("tzcnt".to_string(), tzcnt::SAMPLES);
    samples.insert("unpckhpd".to_string(), unpckhpd::SAMPLES);
    samples.insert("unpckhps".to_string(), unpckhps::SAMPLES);
    samples.insert("unpcklpd".to_string(), unpcklpd::SAMPLES);
    samples.insert("unpcklps".to_string(), unpcklps::SAMPLES);
    samples.insert("vextracti128".to_string(), vextracti128::SAMPLES);
    samples.insert("vpbroadcastb".to_string(), vpbroadcastb::SAMPLES);
    samples.insert("vperm2i128".to_string(), vperm2i128::SAMPLES);
    samples.insert("vpermq".to_string(), vpermq::SAMPLES);
    samples.insert("vpsignw".to_string(), vpsignw::SAMPLES);
    samples.insert("xadd".to_string(), xadd::SAMPLES);
    samples
}

mod aaa;
mod aad;
mod aam;
mod aas;
mod adc;
mod adcx;
mod add;
mod addsd;
mod andn;
mod andnpd;
mod andnps;
mod andpd;
mod andps;
mod bextr;
mod blsi;
mod blsmsk;
mod blsr;
mod bsf;
mod bsr;
mod bswap;
mod bt;
mod btc;
mod btr;
mod bts;
mod bzhi;
mod cmovbe;
mod cmovc;
mod cmovge;
mod cmovl;
mod cmovle;
mod cmovz;
mod cmp;
mod cmps;
mod cmpxchg;
mod cmpxchg16b;
mod cmpxchg8b;
mod comisd;
mod cvtdq2pd;
mod cvttsd2si;
mod dec;
mod div;
mod divsd;
mod enter;
mod extractps;
mod fabs;
mod fadd;
mod faddp;
mod fchs;
mod fcom;
mod fcomp;
mod fcompp;
mod fdiv;
mod fdivr;
mod fdivrp;
mod fild;
mod fld;
mod fld1;
mod fldz;
mod fmul;
mod fmulp;
mod fnstsw;
mod fst;
mod fstp;
mod fsub;
mod fsubp;
mod fsubr;
mod fsubrp;
mod fucom;
mod fucomp;
mod fxch;
mod idiv;
mod imul;
mod inc;
mod lddqu;
mod lea;
mod leave;
mod lods;
mod lzcnt;
mod minsd;
mod mov;
mod movapd;
mod movbe;
mod movd;
mod movddup;
mod movdq2q;
mod movdqa;
mod movdqu;
mod movhlps;
mod movhpd;
mod movhps;
mod movlhps;
mod movlpd;
mod movlps;
mod movmskpd;
mod movmskps;
mod movntdq;
mod movnti;
mod movntpd;
mod movntps;
mod movntq;
mod movq;
mod movq2dq;
mod movs;
mod movsd;
mod movshdup;
mod movsldup;
mod movss;
mod movsx;
mod movupd;
mod movzx;
mod mulsd;
mod mulx;
mod neg;
mod nop;
mod not;
mod packssdw;
mod packsswb;
mod packuswb;
mod paddb;
mod paddd;
mod paddq;
mod paddw;
mod palignr;
mod pand;
mod pandn;
mod pavgb;
mod pavgw;
mod pcmpeqb;
mod pcmpeqd;
mod pcmpeqq;
mod pcmpeqw;
mod pcmpgtb;
mod pcmpgtd;
mod pcmpgtw;
mod pdep;
mod pext;
mod pextrb;
mod pextrd;
mod pextrq;
mod pextrw;
mod pinsrb;
mod pinsrd;
mod pinsrq;
mod pmaddwd;
mod pmaxsb;
mod pmaxsd;
mod pmaxsw;
mod pmaxub;
mod pmaxud;
mod pmaxuw;
mod pminsb;
mod pminsd;
mod pminsw;
mod pminub;
mod pminud;
mod pminuw;
mod pmovmskb;
mod pmovsxbd;
mod pmovsxbq;
mod pmovsxbw;
mod pmovsxdq;
mod pmovsxwd;
mod pmovsxwq;
mod pmovzxbd;
mod pmovzxbq;
mod pmovzxbw;
mod pmovzxdq;
mod pmovzxwd;
mod pmovzxwq;
mod pmulhw;
mod pmulld;
mod pmullw;
mod pmuludq;
mod pop;
mod popcnt;
mod por;
mod pshufb;
mod pshufd;
mod pshufhw;
mod pshuflw;
mod pshufw;
mod pslld;
mod pslldq;
mod psllq;
mod psllw;
mod psrad;
mod psraw;
mod psrld;
mod psrldq;
mod psrlq;
mod psrlw;
mod psubb;
mod psubd;
mod psubq;
mod psubw;
mod ptest;
mod punpckhbw;
mod punpckhdq;
mod punpckhqdq;
mod punpckhwd;
mod punpcklbw;
mod punpckldq;
mod punpcklqdq;
mod punpcklwd;
mod push;
mod pxor;
mod rcl;
mod rcr;
mod ret;
mod rol;
mod ror;
mod rorx;
mod sarx;
mod sbb;
mod scas;
mod setbe;
mod setc;
mod setg;
mod setge;
mod setl;
mod setle;
mod setnz;
mod seto;
mod sets;
mod setz;
mod shl;
mod shld;
mod shlx;
mod shrd;
mod shrx;
mod stos;
mod sub;
mod subsd;
mod system;
mod test;
mod tzcnt;
mod ucomisd;
mod unpckhpd;
mod unpckhps;
mod unpcklpd;
mod unpcklps;
mod vextracti128;
mod vpbroadcastb;
mod vperm2i128;
mod vpermq;
mod vpsignw;
mod xadd;
mod xchg;
mod xor;
