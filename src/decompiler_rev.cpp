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
#include <pthread.h>
#include <openssl/sha.h>
#else
#include <windows.h>
#include <wincrypt.h>
#endif
#include <math.h>
#include <capstone/capstone.h>
#include "json.h"
#include "decompiler_rev.h"

// Very WIP Multi-Threaded Recursive Decompiler

using namespace std;
using namespace binlex;

static pthread_mutex_t DECOMPILER_REV_MUTEX = PTHREAD_MUTEX_INITIALIZER;

typedef struct worker
{
    csh handle;
    cs_err error;
    uint64_t pc;
    const uint8_t *code;
    size_t code_size;

} worker;

typedef struct{
  uint index;
  void *sections;
  uint offset;
} worker_args;

//from https://github.com/capstone-engine/capstone/blob/master/include/capstone/x86.h

#define X86_REL_ADDR(insn) (((insn).detail->x86.operands[0].type == X86_OP_IMM) \
	? (uint64_t)((insn).detail->x86.operands[0].imm) \
	: (((insn).address + (insn).size) + (uint64_t)(insn).detail->x86.disp))

DecompilerREV::DecompilerREV() {
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++) {
        sections[i].offset = 0;
        sections[i].traits = NULL;
        sections[i].traits_count = 0;
        sections[i].data = NULL;
        sections[i].data_size = 0;
        sections[i].threads = 1;
    }
}

bool DecompilerREV::AllocTraits(uint count, uint index) {
    sections[index].traits_count = sections[index].traits_count + count;
    if (realloc(sections[index].traits, sizeof(trait) * sections[index].traits_count) == NULL) {
        return false;
    }
    return true;
}

bool DecompilerREV::Setup(cs_arch arch, cs_mode mode, uint index, uint threads) {
    sections[index].arch = arch;
    sections[index].mode = mode;
    sections[index].threads = threads;
    return true;
}

bool DecompilerREV::Worker(void *args) {

    // Collect Arguments
    worker_args *pArgs = (worker_args *)args;
    uint index = pArgs->index;
    struct Section *sections = (struct Section *)pArgs->sections;

    // This method needs to be static, which means *sections and index must be passed as args

    worker myself;

    // Initialize Decompiler
    myself.error = cs_open(sections[index].arch, sections[index].mode, &myself.handle);
    if (myself.error != CS_ERR_OK) {
        return false;
    }
    myself.error = cs_option(myself.handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (myself.error != CS_ERR_OK) {
        return false;
    }

    // Setup Decompiler Loop
    cs_insn *insn = cs_malloc(myself.handle);
    uint64_t tmp_addr = 0;

    // Get Address from Queue
    uint64_t address = sections[index].discovered.front();
    sections[index].discovered.pop();

    // Seek to the Address
    myself.pc = address;
    myself.code = (uint8_t *)((uint8_t *)sections[index].data + address);
    myself.code_size = sections[index].data_size + address;

    // Check if Function or Block Address
    bool block = IsBlock(sections[index].addresses, address, index);
    bool function = IsFunction(sections[index].addresses, address, index);

    // LOCK
    // Set Address as Visited
    sections[index].visited[address] = 0;
    // UNLOCK

    // Function Decompiler Logic
    while (true){
        // If End of Data Break
        if (myself.pc >= sections[index].data_size) {
            break;
        }
        // Disassemble Instruction
        bool result = cs_disasm_iter(myself.handle, &myself.code, &myself.code_size, &myself.pc, insn);
        // If Instruction Invalid
        if (result == false){
            myself.pc++;
            myself.code = (uint8_t *)((uint8_t *)sections[index].data + myself.pc);
            myself.code_size = sections[index].data_size + myself.pc;
            printf("INVALID INSTRUCTION\n");
            // Append Wildcard Bytes to Both Block and Function Trait
            continue;
        }

        // LOCK MUTEX
        //pthread_mutex_lock(&DECOMPILER_REV_MUTEX);

        // If More Executable Data Add to Queue
        if (result == true && IsEndInsn(insn) == true && myself.pc < sections[index].data_size){
            tmp_addr = myself.pc+sizeof(insn->bytes);
            if (IsVisited(sections[index].visited, tmp_addr, index) == false && tmp_addr < sections[index].data_size){
                sections[index].discovered.push(tmp_addr);
                sections[index].addresses[tmp_addr] = DECOMPILER_REV_OPERAND_TYPE_FUNCTION;
            }
        }
        // Collect Instruction Operands
        CollectInsn(insn, index);

        // UNLOCK MUTEX
        //pthread_mutex_unlock(&DECOMPILER_REV_MUTEX);

        // Debug Print Instruction
        printf("address=0x%" PRIx64 ",block=%d,function=%d,queue=%ld,instruction=%s\t%s\n", insn->address,IsBlock(sections[index].addresses, insn->address, index), IsFunction(sections[index].addresses, insn->address, index), sections[index].discovered.size(), insn->mnemonic, insn->op_str);

        // Collect Block and Function Data Here

        // If Function and End of Function Break
        if (function == true && IsEndInsn(insn) == true){
            if (block == true && IsConditionalInsn(insn) == true){
                // END Block Data
                printf("END\n");
                break;
            }
            // END Function Data
            printf("END\n");
            break;
        }
        // If Block and End of Block Break
        if (block == true && (IsConditionalInsn(insn) == true || IsEndInsn(insn) == true) && function == false){
            // END Block Data
            printf("END\n");
            break;
        }
    }
    cs_free(insn, 1);
    cs_close(&myself.handle);
    return true;
}

void DecompilerREV::Decompile(void* data, size_t data_size, size_t offset, uint index) {

    //pthread_t threads[DECOMPILER_REV_THREADS];

    //pthread_t threads;

    sections[index].data = data;
    sections[index].data_size = data_size;

    sections[index].discovered.push(0);
    sections[index].addresses[0] = DECOMPILER_REV_OPERAND_TYPE_FUNCTION;

    //pthread_create(&threads[i], NULL, Worker, (void *)index);

    worker_args *args = (worker_args *)malloc(sizeof(worker_args));
    args->index = index;
    args->sections = &sections;
    args->offset = offset;
    while(!sections[index].discovered.empty()){
        Worker(args);
    }
    free(args);
    printf("END PROGRAM\n");
}

bool DecompilerREV::IsVisited(map<uint64_t, int> &visited, uint64_t address, uint index) {
    return visited.find(address) != visited.end();
}

bool DecompilerREV::IsEndInsn(cs_insn *insn) {
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

bool DecompilerREV::IsConditionalInsn(cs_insn* insn) {
    switch (insn->id) {
    case X86_INS_JMP:
        return true;
    case X86_INS_JNE:
        return true;
    case X86_INS_JNO:
        return true;
    case X86_INS_JNP:
        return true;
    case X86_INS_JL:
        return true;
    case X86_INS_JLE:
        return true;
    case X86_INS_JG:
        return true;
    case X86_INS_JGE:
        return true;
    case X86_INS_JE:
        return true;
    case X86_INS_JECXZ:
        return true;
    case X86_INS_JCXZ:
        return true;
    case X86_INS_JB:
        return true;
    case X86_INS_JBE:
        return true;
    case X86_INS_JA:
        return true;
    case X86_INS_JAE:
        return true;
    case X86_INS_JNS:
        return true;
    case X86_INS_JO:
        return true;
    case X86_INS_JP:
        return true;
    case X86_INS_JRCXZ:
        return true;
    case X86_INS_JS:
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

// Needs visited, addresses, discovered, data_size (remove index)
void DecompilerREV::CollectOperands(cs_insn* insn, int operand_type, uint index) {
    uint64_t address = X86_REL_ADDR(*insn);
    if (IsVisited(sections[index].visited, address, index) == false && address < sections[index].data_size) {
        sections[index].visited[address] = 0;
        switch(operand_type){
            case DECOMPILER_REV_OPERAND_TYPE_BLOCK:
                sections[index].addresses[address] = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
                sections[index].discovered.push(address);
                break;
            case DECOMPILER_REV_OPERAND_TYPE_FUNCTION:
                sections[index].addresses[address] = DECOMPILER_REV_OPERAND_TYPE_FUNCTION;
                sections[index].discovered.push(address);
                break;
            default:
                break;
        }
    }
}

bool DecompilerREV::IsAddress(map<uint64_t, uint> &addresses, uint64_t address, uint index){
    if (addresses.find(address) == addresses.end()){
        return false;
    }
    return true;
}

bool DecompilerREV::IsFunction(map<uint64_t, uint> &addresses, uint64_t address, uint index){
    if (addresses.find(address) == addresses.end()){
        return false;
    }
    if (addresses.find(address)->second != DECOMPILER_REV_OPERAND_TYPE_FUNCTION){
        return false;
    }
    return true;
}

bool DecompilerREV::IsBlock(map<uint64_t, uint> &addresses, uint64_t address, uint index){
    if (addresses.find(address) == addresses.end()){
        return false;
    }
    if (addresses.find(address)->second == DECOMPILER_REV_OPERAND_TYPE_BLOCK ||
        addresses.find(address)->second == DECOMPILER_REV_OPERAND_TYPE_FUNCTION){
        return true;
    }
    return false;
}

DecompilerREV::~DecompilerREV() {
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++) {
        if (sections[i].traits != NULL) {
            free(sections[i].traits);
            sections[i].traits_count = 0;
        }
    }
}
