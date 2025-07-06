//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

use std::io::Error;
use std::io::ErrorKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mnemonic {
    Add = 0x58,
    AddOvf = 0xD6,
    AddOvfUn = 0xD7,
    And = 0x5F,
    Beq = 0x3B,
    BeqS = 0x2E,
    Bge = 0x3C,
    BgeS = 0x2F,
    BgeUn = 0x41,
    BgeUnS = 0x34,
    Bgt = 0x3D,
    BgtS = 0x30,
    BgtUn = 0x42,
    BgtUnS = 0x35,
    Ble = 0x3E,
    BleS = 0x31,
    BleUn = 0x43,
    BleUnS = 0x36,
    Blt = 0x3F,
    BltS = 0x32,
    BltUn = 0x44,
    BltUnS = 0x37,
    BneUn = 0x40,
    BneUnS = 0x33,
    Box = 0x8C,
    Br = 0x38,
    BrS = 0x2B,
    Break = 0x01,
    BrFalse = 0x39,
    BrFalseS = 0x2C,
    BrTrue = 0x3A,
    BrTrueS = 0x2D,
    Call = 0x28,
    CallI = 0x29,
    CallVirt = 0x6F,
    CastClass = 0x74,
    CkInite = 0xC3,
    ConvI = 0xD3,
    ConvI1 = 0x67,
    ConvI2 = 0x68,
    ConvI4 = 0x69,
    ConvI8 = 0x6A,
    ConvOvfI = 0xD4,
    ConvOvfIUn = 0x8A,
    ConvOvfI1 = 0xB3,
    ConvOvfI1Un = 0x82,
    ConvOvfI2 = 0xB5,
    ConvOvfI2Un = 0x83,
    ConvOvfI4 = 0xB7,
    ConvOvfI4Un = 0x84,
    ConvOvfI8 = 0xB9,
    ConvOvfI8Un = 0x85,
    ConvOvfU = 0xD5,
    ConvOvfUUn = 0x8B,
    ConvOvfU1 = 0xB4,
    ConvOvfU1Un = 0x86,
    ConvOvfU2 = 0xB6,
    ConvOvfU2Un = 0x87,
    ConvOvfU4 = 0xB8,
    ConvOvfU4Un = 0x88,
    ConvOvfU8 = 0xBA,
    ConvOvfU8Un = 0x89,
    ConvRUn = 0x76,
    ConvR4 = 0x6B,
    ConvR8 = 0x6C,
    ConvU = 0xE0,
    ConvU1 = 0xD2,
    ConvU2 = 0xD1,
    ConvU4 = 0x6D,
    ConvU8 = 0x6E,
    Cpobj = 0x70,
    Div = 0x5B,
    DivUn = 0x5C,
    DUP = 0x25,
    End = 0xDC,
    IsInst = 0x75,
    Jmp = 0x27,
    LdArg0 = 0x02,
    LdArg1 = 0x03,
    LdArg2 = 0x04,
    LdArg3 = 0x05,
    LdArgS = 0x0E,
    LdArgAS = 0x0F,
    LdcI4 = 0x20,
    LdcI40 = 0x16,
    LdcI41 = 0x17,
    LdcI42 = 0x18,
    LdcI43 = 0x19,
    LdcI44 = 0x1A,
    LdcI45 = 0x1B,
    LdcI46 = 0x1C,
    LdcI47 = 0x1D,
    LdcI48 = 0x1E,
    LdcI4M1 = 0x15,
    LdcI4S = 0x1F,
    LdcI8 = 0x21,
    LdcR4 = 0x22,
    LdcR8 = 0x23,
    LdElm = 0xA3,
    LdElmI = 0x97,
    LdElmI1 = 0x90,
    LdElmI2 = 0x92,
    LdElmI4 = 0x94,
    LdElmU8 = 0x96,
    LdElmR4 = 0x98,
    LdElmR8 = 0x99,
    LdElmRef = 0x9A,
    LdElmU1 = 0x91,
    LdElmU2 = 0x93,
    LdElmU4 = 0x95,
    LdElmA = 0x8F,
    LdFld = 0x7B,
    LdFldA = 0x7C,
    LdIndI = 0x4D,
    LdIndI1 = 0x46,
    LdIndI2 = 0x48,
    LdIndI4 = 0x4A,
    LdIndU8 = 0x4C,
    LdIndR4 = 0x4E,
    LdIndR8 = 0x4F,
    LdIndRef = 0x50,
    LdIndU1 = 0x47,
    LdIndU2 = 0x49,
    LdIndU4 = 0x4B,
    LdLen = 0x8E,
    LdLoc0 = 0x06,
    LdLoc1 = 0x07,
    LdLoc2 = 0x08,
    LdLoc3 = 0x09,
    LdLocS = 0x11,
    LdLocAS = 0x12,
    LdNull = 0x14,
    LdObj = 0x71,
    LdSFld = 0x7E,
    LdSFldA = 0x7F,
    LdStr = 0x72,
    LdToken = 0xD0,
    Leave = 0xDD,
    LeaveS = 0xDE,
    MkRefAny = 0xC6,
    Mul = 0x5A,
    MulOvf = 0xD8,
    MulOvfUn = 0xD9,
    Neg = 0x65,
    NewArr = 0x8D,
    NewObj = 0x73,
    Nop = 0x00,
    Not = 0x66,
    Or = 0x60,
    Pop = 0x26,
    RefAnyVal = 0xC2,
    Rem = 0x5D,
    RemUn = 0x5E,
    Ret = 0x2A,
    Shl = 0x62,
    Shr = 0x63,
    ShrUn = 0x64,
    StArgS = 0x10,
    StElem = 0xA4,
    StElemI = 0x9B,
    StElemI1 = 0x9C,
    StElemI2 = 0x9D,
    StElemI4 = 0x9E,
    StElemI8 = 0x9F,
    StElemR4 = 0xA0,
    StElemR8 = 0xA1,
    StElemREF = 0xA2,
    StFld = 0x7D,
    StIndI = 0xDF,
    StIndI1 = 0x52,
    StIndI2 = 0x53,
    StIndI4 = 0x54,
    StIndI8 = 0x55,
    StIndR4 = 0x56,
    StIndR8 = 0x57,
    StIndRef = 0x51,
    StLoc0 = 0x0A,
    StLoc1 = 0x0B,
    StLoc2 = 0x0C,
    StLoc3 = 0x0D,
    StObj = 0x81,
    StSFld = 0x80,
    Sub = 0x59,
    SubOvf = 0xDA,
    SubOvfUn = 0xDB,
    Switch = 0x45,
    Throw = 0x7A,
    Unbox = 0x79,
    UnboxAny = 0xA5,
    Xor = 0x61,
    StLocS = 0x13,
    ArgList = 0xfe00,
    Ceq = 0xfe01,
    Cgt = 0xfe02,
    CgtUn = 0xfe03,
    Clt = 0xfe04,
    CltUn = 0xfe05,
    Constrained = 0xfe16,
    CpBlk = 0xfe17,
    EndFilter = 0xfe11,
    InitBlk = 0xfe18,
    InitObj = 0xfe15,
    LdArg = 0xfe09,
    LdArgA = 0xfe0a,
    LdFtn = 0xfe06,
    LdLoc = 0xfe0c,
    LdLocA = 0xfe0d,
    LdVirtFtn = 0xfe07,
    LocAlloc = 0xfe0f,
    No = 0xfe19,
    ReadOnly = 0xfe1e,
    RefAnyType = 0xfe1d,
    ReThrow = 0xfe1a,
    SizeOf = 0xfe1c,
    StArg = 0xfe0b,
    SLoc = 0xfe0e,
    Tail = 0xfe14,
    Unaligned = 0xfe12,
    Volatile = 0xfe13,
}

impl Mnemonic {
    pub const fn all_variants() -> &'static [Self] {
        &[
            Self::Add,
            Self::AddOvf,
            Self::AddOvfUn,
            Self::And,
            Self::Beq,
            Self::BeqS,
            Self::Bge,
            Self::BgeS,
            Self::BgeUn,
            Self::BgeUnS,
            Self::Bgt,
            Self::BgtS,
            Self::BgtUn,
            Self::BgtUnS,
            Self::Ble,
            Self::BleS,
            Self::BleUn,
            Self::BleUnS,
            Self::Blt,
            Self::BltS,
            Self::BltUn,
            Self::BltUnS,
            Self::BneUn,
            Self::BneUnS,
            Self::Box,
            Self::Br,
            Self::BrS,
            Self::Break,
            Self::BrFalse,
            Self::BrFalseS,
            Self::BrTrue,
            Self::BrTrueS,
            Self::Call,
            Self::CallI,
            Self::CallVirt,
            Self::CastClass,
            Self::CkInite,
            Self::ConvI,
            Self::ConvI1,
            Self::ConvI2,
            Self::ConvI4,
            Self::ConvI8,
            Self::ConvOvfI,
            Self::ConvOvfIUn,
            Self::ConvOvfI1,
            Self::ConvOvfI1Un,
            Self::ConvOvfI2,
            Self::ConvOvfI2Un,
            Self::ConvOvfI4,
            Self::ConvOvfI4Un,
            Self::ConvOvfI8,
            Self::ConvOvfI8Un,
            Self::ConvOvfU,
            Self::ConvOvfUUn,
            Self::ConvOvfU1,
            Self::ConvOvfU1Un,
            Self::ConvOvfU2,
            Self::ConvOvfU2Un,
            Self::ConvOvfU4,
            Self::ConvOvfU4Un,
            Self::ConvOvfU8,
            Self::ConvOvfU8Un,
            Self::ConvRUn,
            Self::ConvR4,
            Self::ConvR8,
            Self::ConvU,
            Self::ConvU1,
            Self::ConvU2,
            Self::ConvU4,
            Self::ConvU8,
            Self::Cpobj,
            Self::Div,
            Self::DivUn,
            Self::DUP,
            Self::End,
            Self::IsInst,
            Self::Jmp,
            Self::LdArg0,
            Self::LdArg1,
            Self::LdArg2,
            Self::LdArg3,
            Self::LdArgS,
            Self::LdArgAS,
            Self::LdcI4,
            Self::LdcI40,
            Self::LdcI41,
            Self::LdcI42,
            Self::LdcI43,
            Self::LdcI44,
            Self::LdcI45,
            Self::LdcI46,
            Self::LdcI47,
            Self::LdcI48,
            Self::LdcI4M1,
            Self::LdcI4S,
            Self::LdcI8,
            Self::LdcR4,
            Self::LdcR8,
            Self::LdElm,
            Self::LdElmI,
            Self::LdElmI1,
            Self::LdElmI2,
            Self::LdElmI4,
            Self::LdElmU8,
            Self::LdElmR4,
            Self::LdElmR8,
            Self::LdElmRef,
            Self::LdElmU1,
            Self::LdElmU2,
            Self::LdElmU4,
            Self::LdElmA,
            Self::LdFld,
            Self::LdFldA,
            Self::LdIndI,
            Self::LdIndI1,
            Self::LdIndI2,
            Self::LdIndI4,
            Self::LdIndU8,
            Self::LdIndR4,
            Self::LdIndR8,
            Self::LdIndRef,
            Self::LdIndU1,
            Self::LdIndU2,
            Self::LdIndU4,
            Self::LdLen,
            Self::LdLoc0,
            Self::LdLoc1,
            Self::LdLoc2,
            Self::LdLoc3,
            Self::LdLocS,
            Self::LdLocAS,
            Self::LdNull,
            Self::LdObj,
            Self::LdSFld,
            Self::LdSFldA,
            Self::LdStr,
            Self::LdToken,
            Self::Leave,
            Self::LeaveS,
            Self::MkRefAny,
            Self::Mul,
            Self::MulOvf,
            Self::MulOvfUn,
            Self::Neg,
            Self::NewArr,
            Self::NewObj,
            Self::Nop,
            Self::Not,
            Self::Or,
            Self::Pop,
            Self::RefAnyVal,
            Self::Rem,
            Self::RemUn,
            Self::Ret,
            Self::Shl,
            Self::Shr,
            Self::ShrUn,
            Self::StArgS,
            Self::StElem,
            Self::StElemI,
            Self::StElemI1,
            Self::StElemI2,
            Self::StElemI4,
            Self::StElemI8,
            Self::StElemR4,
            Self::StElemR8,
            Self::StElemREF,
            Self::StFld,
            Self::StIndI,
            Self::StIndI1,
            Self::StIndI2,
            Self::StIndI4,
            Self::StIndI8,
            Self::StIndR4,
            Self::StIndR8,
            Self::StIndRef,
            Self::StLoc0,
            Self::StLoc1,
            Self::StLoc2,
            Self::StLoc3,
            Self::StObj,
            Self::StSFld,
            Self::Sub,
            Self::SubOvf,
            Self::SubOvfUn,
            Self::Switch,
            Self::Throw,
            Self::Unbox,
            Self::UnboxAny,
            Self::Xor,
            Self::StLocS,
            Self::ArgList,
            Self::Ceq,
            Self::Cgt,
            Self::CgtUn,
            Self::Clt,
            Self::CltUn,
            Self::Constrained,
            Self::CpBlk,
            Self::EndFilter,
            Self::InitBlk,
            Self::InitObj,
            Self::LdArg,
            Self::LdArgA,
            Self::LdFtn,
            Self::LdLoc,
            Self::LdLocA,
            Self::LdVirtFtn,
            Self::LocAlloc,
            Self::No,
            Self::ReadOnly,
            Self::RefAnyType,
            Self::ReThrow,
            Self::SizeOf,
            Self::StArg,
            Self::SLoc,
            Self::Tail,
            Self::Unaligned,
            Self::Volatile,
        ]
    }

    pub fn operand_size(&self) -> usize {
        match self {
            Self::Ceq => 0,
            Self::ArgList => 0,
            Self::Cgt => 0,
            Self::CgtUn => 0,
            Self::Clt => 0,
            Self::CltUn => 0,
            Self::Constrained => 32,
            Self::CpBlk => 0,
            Self::EndFilter => 0,
            Self::InitBlk => 0,
            Self::InitObj => 32,
            Self::LdArg => 16,
            Self::LdArgA => 32,
            Self::LdFtn => 32,
            Self::LdLoc => 16,
            Self::LdLocA => 16,
            Self::LdVirtFtn => 32,
            Self::LocAlloc => 0,
            Self::No => 0,
            Self::ReadOnly => 32,
            Self::RefAnyType => 0,
            Self::ReThrow => 0,
            Self::SizeOf => 32,
            Self::StArg => 16,
            Self::Tail => 0,
            Self::Unaligned => 0,
            Self::Volatile => 32,
            Self::Beq => 32,
            Self::BeqS => 8,
            Self::Bge => 32,
            Self::BgeS => 8,
            Self::BgeUn => 32,
            Self::BgeUnS => 8,
            Self::Bgt => 32,
            Self::BgtS => 8,
            Self::Ble => 32,
            Self::BleS => 8,
            Self::BleUn => 32,
            Self::BleUnS => 8,
            Self::Blt => 32,
            Self::BltS => 8,
            Self::BltUn => 32,
            Self::BltUnS => 8,
            Self::Box => 32,
            Self::Br => 32,
            Self::BrS => 8,
            Self::Break => 0,
            Self::BrFalse => 32,
            Self::BrFalseS => 8,
            Self::BrTrue => 32,
            Self::BrTrueS => 8,
            Self::Add => 0,
            Self::AddOvf => 0,
            Self::AddOvfUn => 0,
            Self::And => 0,
            Self::CastClass => 32,
            Self::CkInite => 0,
            Self::ConvI => 0,
            Self::ConvI1 => 0,
            Self::ConvI2 => 0,
            Self::ConvI4 => 0,
            Self::ConvI8 => 0,
            Self::ConvOvfI => 0,
            Self::ConvOvfIUn => 0,
            Self::ConvOvfI1 => 0,
            Self::ConvOvfI1Un => 0,
            Self::ConvOvfI2 => 0,
            Self::ConvOvfI2Un => 0,
            Self::ConvOvfI4 => 0,
            Self::ConvOvfI4Un => 0,
            Self::ConvOvfI8 => 0,
            Self::ConvOvfI8Un => 0,
            Self::ConvOvfU => 0,
            Self::ConvOvfUUn => 0,
            Self::ConvOvfU1 => 0,
            Self::ConvOvfU1Un => 0,
            Self::ConvOvfU2 => 0,
            Self::ConvOvfU2Un => 0,
            Self::ConvOvfU4 => 0,
            Self::ConvOvfU4Un => 0,
            Self::ConvOvfU8 => 0,
            Self::ConvOvfU8Un => 0,
            Self::ConvRUn => 0,
            Self::ConvR4 => 0,
            Self::ConvR8 => 0,
            Self::ConvU => 0,
            Self::ConvU1 => 0,
            Self::ConvU2 => 0,
            Self::ConvU4 => 0,
            Self::ConvU8 => 0,
            Self::Cpobj => 32,
            Self::Div => 0,
            Self::DivUn => 0,
            Self::DUP => 0,
            Self::IsInst => 32,
            Self::Jmp => 32,
            Self::LdArg0 => 0,
            Self::LdArg1 => 0,
            Self::LdArg2 => 0,
            Self::LdArg3 => 0,
            Self::LdArgS => 8,
            Self::LdArgAS => 8,
            Self::LdcI4 => 32,
            Self::LdcI40 => 0,
            Self::LdcI41 => 0,
            Self::LdcI42 => 0,
            Self::LdcI43 => 0,
            Self::LdcI44 => 0,
            Self::LdcI45 => 0,
            Self::LdcI46 => 0,
            Self::LdcI47 => 0,
            Self::LdcI48 => 0,
            Self::LdcI4M1 => 0,
            Self::LdcI4S => 8,
            Self::LdcI8 => 64,
            Self::LdcR4 => 32,
            Self::LdcR8 => 64,
            Self::LdElm => 32,
            Self::LdElmI => 0,
            Self::LdElmI1 => 0,
            Self::LdElmI2 => 0,
            Self::LdElmI4 => 0,
            Self::LdElmU8 => 0,
            Self::LdElmR4 => 0,
            Self::LdElmR8 => 0,
            Self::LdElmRef => 0,
            Self::LdElmU1 => 0,
            Self::LdElmU2 => 0,
            Self::LdElmU4 => 0,
            Self::LdElmA => 32,
            Self::LdFld => 32,
            Self::LdFldA => 32,
            Self::LdIndI => 0,
            Self::LdIndI1 => 0,
            Self::LdIndI2 => 0,
            Self::LdIndI4 => 0,
            Self::LdIndU8 => 0,
            Self::LdIndR4 => 0,
            Self::LdIndR8 => 0,
            Self::LdIndU1 => 0,
            Self::LdIndU2 => 0,
            Self::LdIndU4 => 0,
            Self::LdLen => 0,
            Self::LdLoc0 => 0,
            Self::LdLoc1 => 0,
            Self::LdLoc2 => 0,
            Self::LdLoc3 => 0,
            Self::LdLocS => 8,
            Self::LdLocAS => 8,
            Self::LdNull => 0,
            Self::LdObj => 32,
            Self::LdSFld => 32,
            Self::LdSFldA => 32,
            Self::LdStr => 32,
            Self::LdToken => 32,
            Self::Leave => 32,
            Self::LeaveS => 8,
            Self::MkRefAny => 32,
            Self::Mul => 0,
            Self::MulOvf => 0,
            Self::MulOvfUn => 0,
            Self::Neg => 0,
            Self::NewArr => 32,
            Self::NewObj => 32,
            Self::Nop => 0,
            Self::Not => 0,
            Self::Or => 0,
            Self::Pop => 0,
            Self::RefAnyVal => 32,
            Self::Rem => 0,
            Self::RemUn => 0,
            Self::Ret => 0,
            Self::Shl => 0,
            Self::Shr => 0,
            Self::ShrUn => 0,
            Self::StArgS => 8,
            Self::StElem => 32,
            Self::StElemI => 0,
            Self::StElemI2 => 0,
            Self::StElemI4 => 0,
            Self::StElemI8 => 0,
            Self::StElemR4 => 0,
            Self::StElemR8 => 0,
            Self::StElemREF => 0,
            Self::StFld => 32,
            Self::StIndI => 0,
            Self::StIndI2 => 0,
            Self::StIndI8 => 0,
            Self::StIndR4 => 0,
            Self::StIndR8 => 0,
            Self::StIndRef => 0,
            Self::StLocS => 8,
            Self::StLoc0 => 0,
            Self::StLoc1 => 0,
            Self::StLoc2 => 0,
            Self::StLoc3 => 0,
            Self::StObj => 32,
            Self::StSFld => 32,
            Self::Sub => 0,
            Self::SubOvf => 0,
            Self::SubOvfUn => 0,
            Self::Switch => 32,
            Self::Throw => 0,
            Self::Unbox => 32,
            Self::UnboxAny => 32,
            Self::Xor => 0,
            Self::Call => 32,
            Self::CallI => 32,
            Self::CallVirt => 32,
            Self::BneUnS => 8,
            Self::BneUn => 32,
            Self::BgtUn => 32,
            Self::BgtUnS => 8,
            _ => 0,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::other("not enough bytes to parse mnemonic"));
        }

        let value = bytes[0] as u16;
        for &mnemonic in Self::all_variants() {
            if (mnemonic as u16) == value {
                return Ok(mnemonic);
            }
        }

        if bytes[0] == 0xfe {
            if bytes.len() < 2 {
                return Err(Error::other("not enough bytes for prefix instruction"));
            }
            let value = u16::from_be_bytes([bytes[0], bytes[1]]);
            for &mnemonic in Self::all_variants() {
                if (mnemonic as u16) == value {
                    return Ok(mnemonic);
                }
            }
        }

        Err(Error::new(
            ErrorKind::NotFound,
            "0x{:x}: no matching mnemonic found",
        ))
    }
}
