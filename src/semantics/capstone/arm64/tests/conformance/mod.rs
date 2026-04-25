use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const ARM64_SPEC_MNEMONICS: &str = r#"
abs
adc
adcs
add
addg
addhn
addhn2
addp
addpt
adds
addv
adr
adrp
aesd
aese
aesimc
aesmc
and
ands
asr
asrv
at
autda
autdb
autdza
autdzb
autia
autia1716
autia171615
autiasp
autiasppc
autiaz
autib
autib1716
autib171615
autibsp
autibsppc
autibz
autiza
autizb
axflag
b
b_cond
bc_cond
bcax
bf1cvtl
bf1cvtl2
bf2cvtl
bf2cvtl2
bfc
bfcvt
bfcvtn
bfcvtn2
bfdot
bfi
bfm
bfmlalb
bfmlalt
bfmmla
bfxil
bic
bics
bif
bit
bl
blr
blraa
blraaz
blrab
blrabz
br
braa
braaz
brab
brabz
brb
brk
bsl
bti
cas
casa
casab
casah
casal
casalb
casalh
casb
cash
casl
caslb
caslh
casp
caspa
caspal
caspl
cbnz
cbz
ccmn
ccmp
cfinv
cfp
chkfeat
cinc
cinv
clrbhb
clrex
cls
clz
cmeq
cmge
cmgt
cmhi
cmhs
cmle
cmlt
cmn
cmp
cmpp
cmtst
cneg
cnt
cosp
cpp
cpye
cpyen
cpyern
cpyert
cpyertn
cpyertrn
cpyertwn
cpyet
cpyetn
cpyetrn
cpyetwn
cpyewn
cpyewt
cpyewtn
cpyewtrn
cpyewtwn
cpyfe
cpyfen
cpyfern
cpyfert
cpyfertn
cpyfertrn
cpyfertwn
cpyfet
cpyfetn
cpyfetrn
cpyfetwn
cpyfewn
cpyfewt
cpyfewtn
cpyfewtrn
cpyfewtwn
cpyfm
cpyfmn
cpyfmrn
cpyfmrt
cpyfmrtn
cpyfmrtrn
cpyfmrtwn
cpyfmt
cpyfmtn
cpyfmtrn
cpyfmtwn
cpyfmwn
cpyfmwt
cpyfmwtn
cpyfmwtrn
cpyfmwtwn
cpyfp
cpyfpn
cpyfprn
cpyfprt
cpyfprtn
cpyfprtrn
cpyfprtwn
cpyfpt
cpyfptn
cpyfptrn
cpyfptwn
cpyfpwn
cpyfpwt
cpyfpwtn
cpyfpwtrn
cpyfpwtwn
cpym
cpymn
cpymrn
cpymrt
cpymrtn
cpymrtrn
cpymrtwn
cpymt
cpymtn
cpymtrn
cpymtwn
cpymwn
cpymwt
cpymwtn
cpymwtrn
cpymwtwn
cpyp
cpypn
cpyprn
cpyprt
cpyprtn
cpyprtrn
cpyprtwn
cpypt
cpyptn
cpyptrn
cpyptwn
cpypwn
cpypwt
cpypwtn
cpypwtrn
cpypwtwn
crc32b
crc32cb
crc32ch
crc32cw
crc32cx
crc32h
crc32w
crc32x
csdb
csel
cset
csetm
csinc
csinv
csneg
ctz
dc
dcps1
dcps2
dcps3
dgh
dmb
drps
dsb
dup
dvp
eon
eor
eor3
eret
eretaa
eretab
esb
ext
extr
f1cvtl
f1cvtl2
f2cvtl
f2cvtl2
fabd
fabs
facge
facgt
fadd
faddp
famax
famin
fcadd
fccmp
fccmpe
fcmeq
fcmge
fcmgt
fcmla
fcmle
fcmlt
fcmp
fcmpe
fcsel
fcvt
fcvtas
fcvtau
fcvtl
fcvtl2
fcvtms
fcvtmu
fcvtn
fcvtn2
fcvtns
fcvtnu
fcvtps
fcvtpu
fcvtxn
fcvtxn2
fcvtzs
fcvtzu
fdiv
fdot
fjcvtzs
fmadd
fmax
fmaxnm
fmaxnmp
fmaxnmv
fmaxp
fmaxv
fmin
fminnm
fminnmp
fminnmv
fminp
fminv
fmla
fmlal
fmlal2
fmlalb
fmlallbb
fmlallbt
fmlalltb
fmlalltt
fmlalt
fmls
fmlsl
fmlsl2
fmov
fmsub
fmul
fmulx
fneg
fnmadd
fnmsub
fnmul
frecpe
frecps
frecpx
frint32x
frint32z
frint64x
frint64z
frinta
frinti
frintm
frintn
frintp
frintx
frintz
frsqrte
frsqrts
fscale
fsqrt
fsub
gcsb
gcspopcx
gcspopm
gcspopx
gcspushm
gcspushx
gcsss1
gcsss2
gcsstr
gcssttr
gmi
hint
hlt
hvc
ic
ins
irg
isb
ld1
ld1r
ld2
ld2r
ld3
ld3r
ld4
ld4r
ld64b
ldadd
ldadda
ldaddab
ldaddah
ldaddal
ldaddalb
ldaddalh
ldaddb
ldaddh
ldaddl
ldaddlb
ldaddlh
ldap1
ldapr
ldaprb
ldaprh
ldapur
ldapurb
ldapurh
ldapursb
ldapursh
ldapursw
ldar
ldarb
ldarh
ldaxp
ldaxr
ldaxrb
ldaxrh
ldclr
ldclra
ldclrab
ldclrah
ldclral
ldclralb
ldclralh
ldclrb
ldclrh
ldclrl
ldclrlb
ldclrlh
ldclrp
ldclrpa
ldclrpal
ldclrpl
ldeor
ldeora
ldeorab
ldeorah
ldeoral
ldeoralb
ldeoralh
ldeorb
ldeorh
ldeorl
ldeorlb
ldeorlh
ldg
ldgm
ldiapp
ldlar
ldlarb
ldlarh
ldnp
ldp
ldpsw
ldr
ldraa
ldrab
ldrb
ldrh
ldrsb
ldrsh
ldrsw
ldset
ldseta
ldsetab
ldsetah
ldsetal
ldsetalb
ldsetalh
ldsetb
ldseth
ldsetl
ldsetlb
ldsetlh
ldsetp
ldsetpa
ldsetpal
ldsetpl
ldsmax
ldsmaxa
ldsmaxab
ldsmaxah
ldsmaxal
ldsmaxalb
ldsmaxalh
ldsmaxb
ldsmaxh
ldsmaxl
ldsmaxlb
ldsmaxlh
ldsmin
ldsmina
ldsminab
ldsminah
ldsminal
ldsminalb
ldsminalh
ldsminb
ldsminh
ldsminl
ldsminlb
ldsminlh
ldtr
ldtrb
ldtrh
ldtrsb
ldtrsh
ldtrsw
ldumax
ldumaxa
ldumaxab
ldumaxah
ldumaxal
ldumaxalb
ldumaxalh
ldumaxb
ldumaxh
ldumaxl
ldumaxlb
ldumaxlh
ldumin
ldumina
lduminab
lduminah
lduminal
lduminalb
lduminalh
lduminb
lduminh
lduminl
lduminlb
lduminlh
ldur
ldurb
ldurh
ldursb
ldursh
ldursw
ldxp
ldxr
ldxrb
ldxrh
lsl
lslv
lsr
lsrv
luti2
luti4
madd
maddpt
mla
mls
mneg
mov
movi
movk
movn
movz
mrrs
mrs
msr
msrr
msub
msubpt
mul
mvn
mvni
neg
negs
ngc
ngcs
nop
not
orn
orr
pacda
pacdb
pacdza
pacdzb
pacga
pacia
pacia1716
pacia171615
paciasp
paciasppc
paciaz
pacib
pacib1716
pacib171615
pacibsp
pacibsppc
pacibz
paciza
pacizb
pacm
pacnbiasppc
pacnbibsppc
pmul
pmull
pmull2
prfm
prfum
psb
pssbb
raddhn
raddhn2
rax1
rbit
rcwcas
rcwcasa
rcwcasal
rcwcasl
rcwcasp
rcwcaspa
rcwcaspal
rcwcaspl
rcwclr
rcwclra
rcwclral
rcwclrl
rcwclrp
rcwclrpa
rcwclrpal
rcwclrpl
rcwscas
rcwscasa
rcwscasal
rcwscasl
rcwscasp
rcwscaspa
rcwscaspal
rcwscaspl
rcwsclr
rcwsclra
rcwsclral
rcwsclrl
rcwsclrp
rcwsclrpa
rcwsclrpal
rcwsclrpl
rcwset
rcwseta
rcwsetal
rcwsetl
rcwsetp
rcwsetpa
rcwsetpal
rcwsetpl
rcwsset
rcwsseta
rcwssetal
rcwssetl
rcwssetp
rcwssetpa
rcwssetpal
rcwssetpl
rcwsswp
rcwsswpa
rcwsswpal
rcwsswpl
rcwsswpp
rcwsswppa
rcwsswppal
rcwsswppl
rcwswp
rcwswpa
rcwswpal
rcwswpl
rcwswpp
rcwswppa
rcwswppal
rcwswppl
ret
retaa
retaasppc
retab
retabsppc
rev
rev16
rev32
rev64
rmif
ror
rorv
rprfm
rshrn
rshrn2
rsubhn
rsubhn2
saba
sabal
sabal2
sabd
sabdl
sabdl2
sadalp
saddl
saddl2
saddlp
saddlv
saddw
saddw2
sb
sbc
sbcs
sbfiz
sbfm
sbfx
scvtf
sdiv
sdot
sete
seten
setet
setetn
setf16
setf8
setge
setgen
setget
setgetn
setgm
setgmn
setgmt
setgmtn
setgp
setgpn
setgpt
setgptn
setm
setmn
setmt
setmtn
setp
setpn
setpt
setptn
sev
sevl
sha1c
sha1h
sha1m
sha1p
sha1su0
sha1su1
sha256h
sha256h2
sha256su0
sha256su1
sha512h
sha512h2
sha512su0
sha512su1
shadd
shl
shll
shll2
shrn
shrn2
shsub
sli
sm3partw1
sm3partw2
sm3ss1
sm3tt1a
sm3tt1b
sm3tt2a
sm3tt2b
sm4e
sm4ekey
smaddl
smax
smaxp
smaxv
smc
smin
sminp
sminv
smlal
smlal2
smlsl
smlsl2
smmla
smnegl
smov
smstart
smstop
smsubl
smulh
smull
smull2
sqabs
sqadd
sqdmlal
sqdmlal2
sqdmlsl
sqdmlsl2
sqdmulh
sqdmull
sqdmull2
sqneg
sqrdmlah
sqrdmlsh
sqrdmulh
sqrshl
sqrshrn
sqrshrn2
sqrshrun
sqrshrun2
sqshl
sqshlu
sqshrn
sqshrn2
sqshrun
sqshrun2
sqsub
sqxtn
sqxtn2
sqxtun
sqxtun2
srhadd
sri
srshl
srshr
srsra
ssbb
sshl
sshll
sshll2
sshr
ssra
ssubl
ssubl2
ssubw
ssubw2
st1
st2
st2g
st3
st4
st64b
st64bv
st64bv0
stadd
staddb
staddh
staddl
staddlb
staddlh
stclr
stclrb
stclrh
stclrl
stclrlb
stclrlh
steor
steorb
steorh
steorl
steorlb
steorlh
stg
stgm
stgp
stilp
stl1
stllr
stllrb
stllrh
stlr
stlrb
stlrh
stlur
stlurb
stlurh
stlxp
stlxr
stlxrb
stlxrh
stnp
stp
str
strb
strh
stset
stsetb
stseth
stsetl
stsetlb
stsetlh
stsmax
stsmaxb
stsmaxh
stsmaxl
stsmaxlb
stsmaxlh
stsmin
stsminb
stsminh
stsminl
stsminlb
stsminlh
sttr
sttrb
sttrh
stumax
stumaxb
stumaxh
stumaxl
stumaxlb
stumaxlh
stumin
stuminb
stuminh
stuminl
stuminlb
stuminlh
stur
sturb
sturh
stxp
stxr
stxrb
stxrh
stz2g
stzg
stzgm
sub
subg
subhn
subhn2
subp
subps
subpt
subs
sudot
suqadd
svc
swp
swpa
swpab
swpah
swpal
swpalb
swpalh
swpb
swph
swpl
swplb
swplh
swpp
swppa
swppal
swppl
sxtb
sxth
sxtl
sxtl2
sxtw
sys
sysl
sysp
tbl
tbnz
tbx
tbz
tcancel
tcommit
tlbi
tlbip
trcit
trn1
trn2
tsb
tst
tstart
ttest
uaba
uabal
uabal2
uabd
uabdl
uabdl2
uadalp
uaddl
uaddl2
uaddlp
uaddlv
uaddw
uaddw2
ubfiz
ubfm
ubfx
ucvtf
udf
udiv
udot
uhadd
uhsub
umaddl
umax
umaxp
umaxv
umin
uminp
uminv
umlal
umlal2
umlsl
umlsl2
ummla
umnegl
umov
umsubl
umulh
umull
umull2
uqadd
uqrshl
uqrshrn
uqrshrn2
uqshl
uqshrn
uqshrn2
uqsub
uqxtn
uqxtn2
urecpe
urhadd
urshl
urshr
ursqrte
ursra
usdot
ushl
ushll
ushll2
ushr
usmmla
usqadd
usra
usubl
usubl2
usubw
usubw2
uxtb
uxth
uxtl
uxtl2
uzp1
uzp2
wfe
wfet
wfi
wfit
xaflag
xar
xpacd
xpaci
xpaclri
xtn
xtn2
yield
zip1
zip2
"#;

mod adc;
mod add;
mod addv;
mod adrp;
mod and;
mod asr;
mod b;
mod b_cc;
mod b_cs;
mod b_eq;
mod b_ge;
mod b_gt;
mod b_hi;
mod b_hs;
mod b_le;
mod b_lo;
mod b_ls;
mod b_lt;
mod b_mi;
mod b_ne;
mod b_pl;
mod b_vc;
mod b_vs;
mod bfi;
mod bfxil;
mod bic;
mod bics;
mod bl;
mod blr;
mod br;
mod cbnz;
mod cbz;
mod ccmn;
mod ccmp;
mod cinc;
mod clz;
mod cmeq;
mod cmhi;
mod cmn;
mod cmp;
mod cneg;
mod cnt;
mod csel;
mod cset;
mod csetm;
mod csinc;
mod csinv;
mod csneg;
mod dup;
mod eon;
mod eor;
mod extr;
mod fabs;
mod fadd;
mod fccmp;
mod fcmp;
mod fcmpe;
mod fcvtzs;
mod fcvtzu;
mod fdiv;
mod fmadd;
mod fmax;
mod fmin;
mod fmov;
mod fmsub;
mod fmul;
mod fneg;
mod fnmul;
mod fsub;
mod ld1;
mod ldar;
mod ldarb;
mod ldarh;
mod ldnp;
mod ldp;
mod ldpsw;
mod ldr;
mod ldrb;
mod ldrh;
mod ldrsb;
mod ldrsh;
mod ldrsw;
mod ldtr;
mod ldtrb;
mod ldtrh;
mod ldtrsb;
mod ldtrsh;
mod ldtrsw;
mod ldur;
mod ldurb;
mod ldurh;
mod ldursb;
mod ldursh;
mod ldursw;
mod lsl;
mod lsr;
mod madd;
mod mneg;
mod mov;
mod movi;
mod movk;
mod movn;
mod movz;
mod mrs;
mod msr;
mod msub;
mod mul;
mod mvn;
mod neg;
mod orn;
mod orr;
mod rbit;
mod rev16;
mod rev32;
mod rev64;
mod rev;
mod ret;
mod ror;
mod sbc;
mod sbfiz;
mod sbfx;
mod scvtf;
mod sdiv;
mod smaddl;
mod smsubl;
mod smulh;
mod smull;
mod sshll;
mod stlrh;
mod stnp;
mod stp;
mod str;
mod strb;
mod strh;
mod sttr;
mod sttrb;
mod sttrh;
mod stur;
mod sturb;
mod sturh;
mod sub;
mod sxtb;
mod sxth;
mod sxtw;
mod tbnz;
mod tbz;
mod tst;
mod uaddlv;
mod ubfiz;
mod ubfx;
mod ucvtf;
mod udiv;
mod umaddl;
mod umsubl;
mod umulh;
mod umull;
mod uxtb;
mod uxth;
mod uzp1;

const ARM64_IGNORED_MNEMONICS: &[&str] = &[
    // Hardware-specific, privileged, trap, or exception-state instructions.
    "at",
    "bc_cond",
    "brb",
    "brk",
    "bti",
    "cfp",
    "clrbhb",
    "clrex",
    "cosp",
    "cpp",
    "csdb",
    "dc",
    "dcps1",
    "dcps2",
    "dcps3",
    "dgh",
    "dmb",
    "drps",
    "dsb",
    "dvp",
    "eret",
    "eretaa",
    "eretab",
    "esb",
    "gcsb",
    "gcspopcx",
    "gcspopm",
    "gcspopx",
    "gcspushm",
    "gcspushx",
    "gcsss1",
    "gcsss2",
    "gcsstr",
    "hlt",
    "hvc",
    "ic",
    "isb",
    "mrrs",
    "msrr",
    "sev",
    "sevl",
    "smc",
    "smstart",
    "smstop",
    "svc",
    "sys",
    "sysl",
    "tlbi",
    "wfe",
    "wfet",
    "wfi",
    "wfit",
    "yield",
];

#[test]
fn arm64_conformance_mnemonic_coverage_stats() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/semantics/capstone/arm64/tests/conformance");
    let spec_mnemonics = ARM64_SPEC_MNEMONICS
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let ignored_mnemonics = ARM64_IGNORED_MNEMONICS
        .iter()
        .map(|mnemonic| (*mnemonic).to_string())
        .collect::<BTreeSet<_>>();
    let effective_spec_mnemonics = spec_mnemonics
        .difference(&ignored_mnemonics)
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut covered_files = fs::read_dir(&directory)
        .expect("read arm64 conformance directory")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension().is_some_and(|ext| ext == "rs")
                && path.file_name().is_some_and(|name| name != "mod.rs"))
            .then(|| path.file_stem().unwrap().to_string_lossy().to_string())
        })
        .collect::<BTreeSet<_>>();

    if covered_files.iter().any(|name| {
        name.starts_with("b_") && !matches!(name.as_str(), "b" | "bl" | "blr" | "br")
    }) {
        covered_files.insert("b_cond".to_string());
    }

    let missing = effective_spec_mnemonics
        .difference(&covered_files)
        .cloned()
        .collect::<Vec<_>>();
    let extra = covered_files
        .difference(&effective_spec_mnemonics)
        .cloned()
        .collect::<Vec<_>>();

    println!("arm64 conformance coverage stats");
    println!("spec mnemonics: {}", spec_mnemonics.len());
    println!("ignored mnemonics: {}", ignored_mnemonics.len());
    println!("effective spec mnemonics: {}", effective_spec_mnemonics.len());
    println!(
        "covered mnemonics: {}",
        effective_spec_mnemonics.intersection(&covered_files).count()
    );
    println!("missing mnemonics: {}", missing.len());
    println!("extra mnemonic files: {}", extra.len());
    if !extra.is_empty() {
        println!("extra: {}", extra.join(", "));
    }
    println!(
        "next 10 missing: {}",
        missing.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
    );
}
