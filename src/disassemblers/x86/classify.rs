// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

pub fn is_return_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "ret" | "retf" | "retfq" | "iret" | "iretd" | "iretq"
    )
}

pub fn is_privilege_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "hlt"
            | "in"
            | "insb"
            | "insw"
            | "insd"
            | "out"
            | "outsb"
            | "outsw"
            | "outsd"
            | "rdmsr"
            | "wrmsr"
            | "rdpmc"
            | "rdtsc"
            | "lgdt"
            | "lldt"
            | "ltr"
            | "lmsw"
            | "clts"
            | "invd"
            | "invlpg"
            | "wbinvd"
    )
}

pub fn is_nop_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "nop" | "fnop")
}

pub fn is_trap_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "int3" | "ud2" | "int1" | "into")
}

pub fn is_wildcard_mnemonic(mnemonic: &str) -> bool {
    is_nop_mnemonic(mnemonic) || is_trap_mnemonic(mnemonic)
}

pub fn is_load_address_mnemonic(mnemonic: &str) -> bool {
    mnemonic == "lea"
}

pub fn is_call_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "call" | "lcall")
}

pub fn is_unconditional_jump_mnemonic(mnemonic: &str) -> bool {
    mnemonic == "jmp"
}

pub fn is_conditional_jump_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "jne"
            | "jno"
            | "jnp"
            | "jl"
            | "jle"
            | "jg"
            | "jge"
            | "je"
            | "jecxz"
            | "jcxz"
            | "jb"
            | "jbe"
            | "ja"
            | "jae"
            | "jp"
            | "jo"
            | "js"
            | "jns"
            | "jrcxz"
            | "loope"
            | "loopne"
            | "loop"
    )
}

pub fn is_jump_mnemonic(mnemonic: &str) -> bool {
    is_conditional_jump_mnemonic(mnemonic) || is_unconditional_jump_mnemonic(mnemonic)
}
