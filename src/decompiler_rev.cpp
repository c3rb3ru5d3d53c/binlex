#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <iomanip>
#ifndef _WIN32
#include <openssl/sha.h>
#else
#include <windows.h>
#include <wincrypt.h>
#endif
#include <math.h>
#include <capstone/capstone.h>
#include "json.h"
#include "decompiler_rev.h"
using namespace std;
using namespace binlex;

// Very WIP Recursive Decompiler

//from https://github.com/capstone-engine/capstone/blob/master/include/capstone/x86.h

#define X86_REL_ADDR(insn) (((insn).detail->x86.operands[0].type == X86_OP_IMM) \
	? (uint64_t)((insn).detail->x86.operands[0].imm) \
	: (((insn).address + (insn).size) + (uint64_t)(insn).detail->x86.disp))

DecompilerREV::DecompilerREV() {
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++) {
        sections[i].handle = 0;
        sections[i].offset = 0;
        sections[i].pc = 0;
        sections[i].traits = NULL;
        sections[i].traits_count = 0;
        sections[i].data = NULL;
        sections[i].code = NULL;
        sections[i].code_size = 0;
        sections[i].data_size = 0;
    }
}

bool DecompilerREV::AllocTraits(uint count, uint index) {
    sections[index].traits_count = sections[index].traits_count + count;
    if (realloc(sections[index].traits, sizeof(trait) * sections[index].traits_count) == NULL) {
        return false;
    }
    return true;
}

bool DecompilerREV::Setup(cs_arch arch, cs_mode mode, uint index) {
    sections[index].status = cs_open(arch, mode, &sections[index].handle);
    if (sections[index].status != CS_ERR_OK) {
        return false;
    }
    sections[index].status = cs_option(sections[index].handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (sections[index].status != CS_ERR_OK) {
        return false;
    }
    return true;
}

void DecompilerREV::Seek(uint64_t address, size_t data_size, uint index) {
    sections[index].pc = address;
    sections[index].code_size = data_size - address;
    sections[index].code = (uint8_t*)sections[index].data;
    sections[index].code = (uint8_t*)(sections[index].code + address);
}

uint DecompilerREV::Decompile(void* data, size_t data_size, size_t data_offset, uint index) {
    sections[index].pc = 0;
    sections[index].data = data;
    sections[index].data_size = data_size;
    sections[index].code_size = data_size;
    sections[index].code = (uint8_t*)data;
    cs_insn* insn = cs_malloc(sections[index].handle);
    uint64_t tmp_addr = 0;
    while (true) {
        if (sections[index].pc >= data_size && sections[index].discovered.empty()) {
            break;
        }
        if (sections[index].pc >= data_size && !sections[index].discovered.empty()){
            tmp_addr = sections[index].discovered.front();
            sections[index].discovered.pop();
            Seek(tmp_addr, data_size, index);
            continue;
        }
        bool result = cs_disasm_iter(sections[index].handle, &sections[index].code, &sections[index].code_size, &sections[index].pc, insn);
        if (result == false){
            // Handle Invalid Instructions
            Seek(sections[index].pc+1, data_size, index);
            continue;
        }
        if (result == true && IsEndInsn(insn) == true && sections[index].pc < data_size){
            // If More Executable Data Available Continue
            Seek(sections[index].pc+sizeof(insn->bytes), data_size, index);
            continue;
        }
        uint operand_type = CollectInsn(insn, index);
        if (IsEndInsn(insn) == true) {
            if (!sections[index].discovered.empty()) {
                tmp_addr = sections[index].discovered.front();
                sections[index].discovered.pop();
                Seek(tmp_addr, data_size, index);
            }
        }
        printf("qsize: %ld, 0x%" PRIx64 ":\t%s\t\t%s\n", sections[index].discovered.size(), insn->address, insn->mnemonic, insn->op_str);
    }
    cs_free(insn, 1);
    return sections[index].pc;
}

uint64_t DecompilerREV::PushBlock(uint64_t address, uint index) {
    sections[index].blocks.push_back(address);
    return address;
}

uint64_t DecompilerREV::PushFunction(uint64_t address, uint index) {
    sections[index].functions.push_back(address);
    return address;
}

bool DecompilerREV::IsVisited(uint64_t address, uint index) {
    return sections[index].visited.find(address) != sections[index].visited.end();
}

bool DecompilerREV::IsEndInsn(cs_insn* insn) {
    switch (insn->id) {
    case X86_INS_RET:
        return true;
    case X86_INS_RETF:
        return true;
    case X86_INS_RETFQ:
        return true;
    case X86_INS_IRET:
        return true;
    case X86_INS_IRETD:
        return true;
    case X86_INS_IRETQ:
        return true;
    default:
        break;
    }
    return false;
}

uint DecompilerREV::CollectInsn(cs_insn* insn, uint index) {
    uint result = DECOMPILER_REV_OPERAND_TYPE_UNSET;
    switch (insn->id) {
    case X86_INS_JMP:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNO:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNP:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JL:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JLE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JG:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JGE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JECXZ:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JCXZ:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JB:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JBE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JA:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JAE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNS:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JO:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JP:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JRCXZ:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JS:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_CALL:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_FUNCTION, index);
        result = DECOMPILER_REV_OPERAND_TYPE_FUNCTION;
        break;
    default:
        return result;
    }
    return result;
}

void DecompilerREV::CollectOperands(cs_insn* insn, int operand_type, uint index) {
    uint64_t address = X86_REL_ADDR(*insn);
    if (!IsVisited(address, index)) {
        sections[index].visited[address] = 0;
        switch(operand_type){
            case DECOMPILER_REV_OPERAND_TYPE_BLOCK:
                sections[index].blocks.push_back(address);
                sections[index].discovered.push(address);
                break;
            case DECOMPILER_REV_OPERAND_TYPE_FUNCTION:
                sections[index].functions.push_back(address);
                sections[index].discovered.push(address);
                break;
            default:
                break;
        }
    }
}

void DecompilerREV::CollectImm(int64_t imm, int operand_type, uint index) {
    switch (operand_type) {
    case DECOMPILER_REV_OPERAND_TYPE_BLOCK:
        sections[index].blocks.push_back(imm);
        break;
    case DECOMPILER_REV_OPERAND_TYPE_FUNCTION:
        sections[index].functions.push_back(imm);
        break;
    default:
        break;
    }
}

DecompilerREV::~DecompilerREV() {
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++) {
        if (sections[i].traits != NULL) {
            free(sections[i].traits);
            sections[i].traits_count = 0;
        }
        if (sections[i].handle != 0) {
            cs_close(&sections[i].handle);
        }
    }
}
