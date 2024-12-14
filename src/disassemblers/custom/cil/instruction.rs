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
use crate::disassemblers::custom::cil::Mnemonic;
use std::collections::BTreeSet;
use crate::Binary;

pub struct Instruction <'instruction> {
    pub mnemonic: Mnemonic,
    bytes: &'instruction [u8],
    pub address: u64,
}

impl <'instruction> Instruction <'instruction> {
    pub fn new(bytes: &'instruction [u8], address: u64) -> Result<Self, Error> {
        let mnemonic = Mnemonic::from_bytes(bytes)?;
        Ok(Self {mnemonic, bytes, address})
    }

    pub fn pattern(&self) -> String {
        if self.is_wildcard() { return "??".repeat(self.size()); }
        if self.is_metadata_token_wildcard_instruction() {
            let mut pattern = Binary::to_hex(&self.mnemonic_bytes());
            pattern.push_str(&"??".repeat(self.operand_size() - 1));
            pattern.push_str(&Binary::to_hex(&vec![*self.operand_bytes().last().unwrap()]));
            return pattern;
        }
        let mut pattern = Binary::to_hex(&self.mnemonic_bytes());
        pattern.push_str(&"??".repeat(self.operand_size()));
        pattern
    }

    pub fn mnemonic_bytes(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        for byte in &self.bytes[..self.mnemonic_size()] {
            result.push(*byte);
        }
        result
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        for byte in &self.bytes[..self.mnemonic_size() + self.operand_size()] {
            result.push(*byte);
        }
        result
    }

    pub fn operand_bytes(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        for byte in &self.bytes[self.mnemonic_size()..self.mnemonic_size() + self.operand_size()] {
            result.push(*byte);
        }
        result
    }

    pub fn edges(&self) -> usize {
        if self.is_unconditional_jump() {
            return 1;
        }
        if self.is_return() {
            return 1;
        }
        if self.is_conditional_jump() {
            return 2;
        }
        return 0;
    }

    pub fn size(&self) -> usize {
        self.mnemonic_size() + self.operand_size()
    }

    pub fn operand_size(&self) -> usize {
        if self.is_switch() {
            let count = self.bytes
                .get(self.mnemonic_size()..self.mnemonic_size() + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .map(|v| v as u32).unwrap();
            return 4 + (count as usize * 4);
        }
        self.mnemonic.operand_size() / 8
    }

    pub fn mnemonic_size(&self) -> usize {
        if self.mnemonic as u16 >> 8 == 0xfe {
            return 2;
        }
        return 1;
    }

    pub fn is_wildcard(&self) -> bool {
        self.is_nop()
    }

    pub fn is_nop(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Nop => true,
            _ => false,
        }
    }

    pub fn is_jump(&self) -> bool {
        self.is_conditional_jump() || self.is_unconditional_jump()
    }

    pub fn next(&self) -> Option<u64> {
        if self.is_unconditional_jump() || self.is_return() || self.is_switch() { return None; }
        Some(self.address + self.size() as u64)
    }

    pub fn to(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();

        if self.is_switch() {
            let address = self.address as i64;
            let count = self.bytes
                .get(self.mnemonic_size()..self.mnemonic_size() + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .map(|v| v as u32).unwrap();
            for index in 1..=count {
                let start = self.mnemonic_size() + (index as usize * 4);
                let end = start + 4;

                let relative_offset = self.bytes
                    .get(start..end)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(i32::from_le_bytes)
                    .unwrap();

                result.insert(
                    address.wrapping_add(relative_offset as i64) as u64
                    + self.size() as u64,
                );
            }
        } else if self.is_jump() {
            let operand_bytes = self.operand_bytes();
            let address = self.address as i64;
            let relative_offset = match self.operand_size() {
                1 => {
                    operand_bytes.get(0).map(|&b| i8::from_le_bytes([b]) as i64)
                }
                2 => {
                    operand_bytes
                        .get(..2)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(i16::from_le_bytes)
                        .map(|v| v as i64)
                }
                4 => {
                    operand_bytes
                        .get(..4)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(i32::from_le_bytes)
                        .map(|v| v as i64)
                }
                _ => None,
            };
            if let Some(relative) = relative_offset {
                result.insert(address.wrapping_add(relative) as u64 + self.size() as u64);
            }
        }
        result
    }

    pub fn is_switch(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Switch => true,
            _ => false,
        }
    }

    pub fn is_metadata_token_wildcard_instruction(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Call => true,
            Mnemonic::CallVirt => true,
            Mnemonic::LdSFld => true,
            Mnemonic::LdFld => true,
            Mnemonic::NewObj => true,
            _ => false,
        }
    }

    pub fn get_call_metadata_token(&self) -> Option<u32> {
        if matches!(self.mnemonic, Mnemonic::Call | Mnemonic::CallVirt) {
            let operand_bytes = self.operand_bytes();
            if operand_bytes.len() >= 4 {
                return Some(u32::from_le_bytes([
                    operand_bytes[0],
                    operand_bytes[1],
                    operand_bytes[2],
                    operand_bytes[3],
                ]));
            }
        }
        None
    }

    pub fn is_conditional_jump(&self) -> bool {
        match self.mnemonic {
            Mnemonic::BrFalse => true,
            Mnemonic::BrFalseS => true,
            Mnemonic::BrTrue => true,
            Mnemonic::BrTrueS => true,
            Mnemonic::BneUn => true,
            Mnemonic::BneUnS => true,
            Mnemonic::Blt => true,
            Mnemonic::BltS => true,
            Mnemonic::BltUn => true,
            Mnemonic::BltUnS => true,
            Mnemonic::Beq => true,
            Mnemonic::BeqS => true,
            Mnemonic::Bge => true,
            Mnemonic::BgeS => true,
            Mnemonic::BgeUn => true,
            Mnemonic::BgeUnS => true,
            Mnemonic::Bgt => true,
            Mnemonic::BgtS => true,
            Mnemonic::BgtUn => true,
            Mnemonic::BgtUnS => true,
            Mnemonic::Ble => true,
            Mnemonic::BleS => true,
            Mnemonic::BleUn => true,
            Mnemonic::BleUnS => true,
            _ => false,
        }
    }

    pub fn is_return(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Ret => true,
            Mnemonic::Throw => true,
            _ => false,
        }
    }

    pub fn is_call(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Call => true,
            Mnemonic::CallI => true,
            Mnemonic::CallVirt => true,
            _ => false,
        }
    }

    pub fn is_unconditional_jump(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Br => true,
            Mnemonic::Jmp => true,
            Mnemonic::BrS => true,
            Mnemonic::Leave => true,
            Mnemonic::LeaveS => true,
            _ => false,
        }
    }
}
