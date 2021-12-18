#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <iomanip>
#if defined(__linux__) || defined(__APPLE__)
#include <pthread.h>
#include <openssl/sha.h>
#elif _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif
#include <unistd.h>
#include <math.h>
#include <capstone/capstone.h>
#include "json.h"
#include "decompiler_rev.h"

// Very WIP Multi-Threaded Recursive Decompiler

using namespace std;
using namespace binlex;
using json = nlohmann::json;

static pthread_mutex_t DECOMPILER_REV_MUTEX = PTHREAD_MUTEX_INITIALIZER;

//from https://github.com/capstone-engine/capstone/blob/master/include/capstone/x86.h

#define X86_REL_ADDR(insn) (((insn).detail->x86.operands[0].type == X86_OP_IMM) \
	? (uint64_t)((insn).detail->x86.operands[0].imm) \
	: (((insn).address + (insn).size) + (uint64_t)(insn).detail->x86.disp))

DecompilerREV::DecompilerREV() {
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++) {
        sections[i].offset = 0;
        sections[i].traits = NULL;
        sections[i].ntraits = 0;
        sections[i].data = NULL;
        sections[i].data_size = 0;
        sections[i].threads = 1;
        sections[i].thread_cycles = 1;
        sections[i].thread_sleep = 500;
    }
}

void * DecompilerREV::AppendTrait(struct Trait *trait, struct Section *sections, uint index){
    sections[index].traits = (struct Trait **)realloc(sections[index].traits, sizeof(struct Trait *) * sections[index].ntraits + 1);
    if (sections[index].traits == NULL){
        fprintf(stderr, "[x] trait realloc failed\n");
        exit(1);
    }
    sections[index].traits[sections[index].ntraits] = (struct Trait *)malloc(sizeof(struct Trait));
    if (sections[index].traits[sections[index].ntraits] == NULL){
        fprintf(stderr, "[x] trait malloc failed\n");
        exit(1);
    }
    // Append Trait
    trait->trait = (char *)malloc(strlen(trait->tmp_trait.c_str())+1);
    if (trait->trait == NULL){
        fprintf(stderr, "[x] trait malloc failed\n");
    }
    memset(trait->trait, 0, strlen(trait->tmp_trait.c_str())+1);
    if (memcpy(trait->trait, trait->tmp_trait.c_str(), strlen(trait->tmp_trait.c_str())) == NULL){
        fprintf(stderr, "[x] trait memcpy failed\n");
    }
    // Append Bytes
    trait->bytes = (char *)malloc(strlen(trait->tmp_bytes.c_str())+1);
    if (trait->bytes == NULL){
        fprintf(stderr, "[x] trait malloc failed\n");
    }
    memset(trait->bytes, 0, strlen(trait->tmp_bytes.c_str())+1);
    if (memcpy(trait->bytes, trait->tmp_bytes.c_str(), strlen(trait->tmp_bytes.c_str())) == NULL){
        fprintf(stderr, "[x] trait memcpy failed\n");
    }
    // asdf
    if (memcpy(sections[index].traits[sections[index].ntraits], trait, sizeof(struct Trait)) == NULL){
        fprintf(stderr, "[x] trait memcpy failed\n");
        exit(1);
    }
    sections[index].ntraits++;
    trait->trait = (char *)trait->tmp_trait.c_str();
    return (void *)sections[index].traits[sections[index].ntraits];
}

bool DecompilerREV::Setup(cs_arch arch, cs_mode mode, uint threads, uint thread_cycles, useconds_t thread_sleep, uint index){
    sections[index].arch = arch;
    sections[index].mode = mode;
    sections[index].threads = threads;
    sections[index].thread_cycles = thread_cycles;
    sections[index].thread_sleep = thread_sleep;
    return true;
}

void DecompilerREV::PrintTrait(struct Trait *trait, bool pretty){
    json data;
    data["type"] = trait->type;
    data["bytes"] = trait->bytes;
    data["trait"] = trait->trait;
    data["edges"] = trait->edges;
    data["blocks"] = trait->blocks;
    data["instructions"] = trait->instructions;
    data["size"] = trait->size;
    data["offset"] = trait->offset;
    data["invalid_instructions"] = trait->invalid_instructions;
    if (pretty == false){
        cout << data.dump() << endl;
    } else {
        cout << data.dump(4) << endl;
    }
}

void * DecompilerREV::Worker(void *args) {

    worker myself;
    worker_args *pArgs = (worker_args *)args;
    uint index = pArgs->index;
    struct Section *sections = (struct Section *)pArgs->sections;

    struct Trait b_trait;
    struct Trait f_trait;

    // struct Trait *b_trait;
    // b_trait = new Trait;

    b_trait.type = (char *)"block";
    ClearTrait(&b_trait);
    f_trait.type = (char *)"function";
    ClearTrait(&f_trait);

    myself.error = cs_open(sections[index].arch, sections[index].mode, &myself.handle);
    if (myself.error != CS_ERR_OK) {
        return NULL;
    }
    myself.error = cs_option(myself.handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (myself.error != CS_ERR_OK) {
        return NULL;
    }

    int thread_cycles = 0;
    cs_insn *insn = cs_malloc(myself.handle);
    while (true){

        uint64_t tmp_addr = 0;
        uint64_t address = 0;

        #if defined(__linux__) || defined(__APPLE__)
        pthread_mutex_lock(&DECOMPILER_REV_MUTEX);
        #endif
        if (!sections[index].discovered.empty()){
            address = sections[index].discovered.front();
            sections[index].discovered.pop();
            sections[index].visited[address] = DECOMPILER_REV_VISITED_ANALYZED;
        } else {
            #if defined(__linux__) || defined(__APPLE__)
            pthread_mutex_unlock(&DECOMPILER_REV_MUTEX);
            #endif
            thread_cycles++;
            if (thread_cycles == sections[index].thread_cycles){
                break;
            }
            usleep(sections[index].thread_sleep);
            continue;
        }
        #if defined(__linux__) || defined(__APPLE__)
        pthread_mutex_unlock(&DECOMPILER_REV_MUTEX);
        #endif

        myself.pc = address;
        myself.code = (uint8_t *)((uint8_t *)sections[index].data + address);
        myself.code_size = sections[index].data_size + address;

        bool block = IsBlock(sections[index].addresses, address);
        bool function = IsFunction(sections[index].addresses, address);

        while(true) {
            uint edges = 0;

            if (myself.pc >= sections[index].data_size) {
                break;
            }

            bool result = cs_disasm_iter(myself.handle, &myself.code, &myself.code_size, &myself.pc, insn);

            b_trait.instructions++;
            f_trait.instructions++;

            if (result == true){
                // Need to Wildcard Traits Here
                if (IsWildcardInsn(insn) == true){
                    b_trait.tmp_trait = b_trait.tmp_trait + Wildcards(insn->size) + " ";
                    f_trait.tmp_trait = f_trait.tmp_trait + Wildcards(insn->size) + " ";
                } else {
                    b_trait.tmp_trait = b_trait.tmp_trait + WildcardInsn(insn) + " ";
                    f_trait.tmp_trait = f_trait.tmp_trait + WildcardInsn(insn) + " ";
                }
                b_trait.tmp_bytes = b_trait.tmp_bytes + HexdumpBE(insn->bytes, insn->size) + " ";
                f_trait.tmp_bytes = f_trait.tmp_bytes + HexdumpBE(insn->bytes, insn->size) + " ";
                edges = IsConditionalInsn(insn);
                b_trait.edges = b_trait.edges + edges;
                f_trait.edges = f_trait.edges + edges;
                if (edges > 0){
                    b_trait.blocks++;
                    f_trait.blocks++;
                }
            }

            if (result == false){
                b_trait.invalid_instructions++;
                f_trait.invalid_instructions++;
                b_trait.tmp_bytes = b_trait.tmp_bytes + HexdumpBE(myself.code, 1) + " ";
                f_trait.tmp_bytes = f_trait.tmp_bytes + HexdumpBE(myself.code, 1) + " ";
                b_trait.tmp_trait = b_trait.tmp_trait + Wildcards(1) + " ";
                f_trait.tmp_trait = f_trait.tmp_trait + Wildcards(1) + " ";
                myself.pc++;
                myself.code = (uint8_t *)((uint8_t *)sections[index].data + myself.pc);
                myself.code_size = sections[index].data_size + myself.pc;
                continue;
            }

            #if defined(__linux__) || defined(__APPLE__)
            pthread_mutex_lock(&DECOMPILER_REV_MUTEX);
            #endif
            if (result == true && IsEndInsn(insn) == true && myself.pc < sections[index].data_size) {
                tmp_addr = myself.pc+sizeof(insn->bytes);
                if (IsVisited(sections[index].visited, tmp_addr) == false &&
                    tmp_addr < sections[index].data_size) {
                    sections[index].discovered.push(tmp_addr);
                    sections[index].addresses[tmp_addr] = DECOMPILER_REV_OPERAND_TYPE_FUNCTION;
                    sections[index].visited[tmp_addr] = DECOMPILER_REV_VISITED_QUEUED;
                }
            }
            CollectInsn(insn, sections, index);
            //printf("address=0x%" PRIx64 ",block=%d,function=%d,queue=%ld,instruction=%s\t%s\n", insn->address,IsBlock(sections[index].addresses, insn->address), IsFunction(sections[index].addresses, insn->address), sections[index].discovered.size(), insn->mnemonic, insn->op_str);

            #if defined(__linux__) || defined(__APPLE__)
            pthread_mutex_unlock(&DECOMPILER_REV_MUTEX);
            #endif
            if (block == true && IsConditionalInsn(insn) > 0){
                b_trait.tmp_trait = TrimRight(b_trait.tmp_trait);
                b_trait.tmp_bytes = TrimRight(b_trait.tmp_bytes);
                b_trait.size = GetByteSize(b_trait.tmp_bytes);
                b_trait.offset = sections[index].offset + myself.pc - b_trait.size;
                if (b_trait.blocks == 0){
                    b_trait.blocks++;
                }
                #if defined(__linux__) || defined(__APPLE__)
                pthread_mutex_lock(&DECOMPILER_REV_MUTEX);
                #endif
                AppendTrait(&b_trait, sections, index);
                #if defined(__linux__) || defined(__APPLE__)
                pthread_mutex_unlock(&DECOMPILER_REV_MUTEX);
                #endif
                //PrintTrait(&b_trait, false);
                ClearTrait(&b_trait);
                if (function == false){
                    ClearTrait(&f_trait);
                    break;
                }
            }
            if (block == true && IsEndInsn(insn) == true){
                b_trait.tmp_trait = TrimRight(b_trait.tmp_trait);
                b_trait.tmp_bytes = TrimRight(b_trait.tmp_bytes);
                b_trait.size = GetByteSize(b_trait.tmp_bytes);
                b_trait.offset = sections[index].offset + myself.pc - b_trait.size;
                if (b_trait.blocks == 0){
                    b_trait.blocks++;
                }
                #if defined(__linux__) || defined(__APPLE__)
                pthread_mutex_lock(&DECOMPILER_REV_MUTEX);
                #endif
                AppendTrait(&b_trait, sections, index);
                #if defined(__linux__) || defined(__APPLE__)
                pthread_mutex_unlock(&DECOMPILER_REV_MUTEX);
                #endif
                //PrintTrait(&b_trait, false);
                ClearTrait(&b_trait);
            }

            if (function == true && IsEndInsn(insn) == true){
                f_trait.tmp_trait = TrimRight(f_trait.tmp_trait);
                f_trait.tmp_bytes = TrimRight(f_trait.tmp_bytes);
                f_trait.size = GetByteSize(f_trait.tmp_bytes);
                f_trait.offset = sections[index].offset + myself.pc - f_trait.size;
                if (f_trait.blocks == 0){
                    f_trait.blocks++;
                }
                #if defined(__linux__) || defined(__APPLE__)
                pthread_mutex_lock(&DECOMPILER_REV_MUTEX);
                #endif
                AppendTrait(&f_trait, sections, index);
                //PrintTrait(&f_trait, false);
                #if defined(__linux__) || defined(__APPLE__)
                pthread_mutex_unlock(&DECOMPILER_REV_MUTEX);
                #endif
                ClearTrait(&f_trait);
                break;
            }
        }
    }
    cs_free(insn, 1);
    cs_close(&myself.handle);
    return NULL;
}

void DecompilerREV::ClearTrait(struct Trait *trait){
    trait->tmp_bytes.clear();
    trait->edges = 0;
    trait->instructions = 0;
    trait->blocks = 0;
    trait->offset = 0;
    trait->size = 0;
    trait->invalid_instructions = 0;
    trait->tmp_trait.clear();
    trait->trait = NULL;
}

void DecompilerREV::Decompile(void* data, size_t data_size, size_t offset, uint index) {
    sections[index].data = data;
    sections[index].data_size = data_size;

    sections[index].discovered.push(0);
    sections[index].addresses[0] = DECOMPILER_REV_OPERAND_TYPE_FUNCTION;
    sections[index].visited[0] = DECOMPILER_REV_VISITED_QUEUED;

    worker_args *args = (worker_args *)malloc(sizeof(worker_args));
    args->index = index;
    args->sections = &sections;

    #if defined(__linux__) || defined(__APPLE__)
    pthread_t threads[sections[index].threads];
    pthread_attr_t thread_attribs[sections[index].threads];
    #endif

    while (true){
        for (int i = 0; i < sections[index].threads; i++){
            #if defined(__linux__) || defined(__APPLE__)
            pthread_attr_init(&thread_attribs[i]);
            pthread_attr_setdetachstate(&thread_attribs[i], PTHREAD_CREATE_JOINABLE);
            pthread_create(&threads[i], NULL, Worker, args);
            #endif
        }
        for (int i = 0; i < sections[index].threads; i++){
            #if defined(__linux__) || defined(__APPLE__)
            pthread_join(threads[i], NULL);
            #endif
        }
        if (sections[index].discovered.empty()){
            break;
        }
    }
    free(args);
}

string DecompilerREV::WildcardInsn(cs_insn *insn){
    string bytes = HexdumpBE(insn->bytes, insn->size);
    string trait = bytes;
    for (int j = 0; j < insn->detail->x86.op_count; j++){
        cs_x86_op operand = insn->detail->x86.operands[j];
        switch(operand.type){
            case X86_OP_MEM:
                // Wildcard Memory Operands
                {
                    if (operand.mem.disp != 0){
                        trait = WildcardTrait(HexdumpBE(insn->bytes, insn->size), HexdumpMemDisp(operand.mem.disp));
                    }
                    break;
                }
            // Immutables case Strange Lenth Issue
            // case X86_OP_IMM:
            //     // Wildcard Immutable Operands / Scalars
            //     {
            //         string imm = HexdumpMemDisp(operand.imm);
            //         if (imm.length() > 0){
            //             trait = WildcardTrait(HexdumpBE(insn->bytes, insn->size), imm);
            //         }
            //         break;
            //     }
            default:
                break;
        }
    }
    return TrimRight(trait);
}

bool DecompilerREV::IsVisited(map<uint64_t, int> &visited, uint64_t address) {
    return visited.find(address) != visited.end();
}

bool DecompilerREV::IsWildcardInsn(cs_insn *insn){
    switch (insn->id) {
        case X86_INS_NOP:
            return true;
        default:
            break;
    }
    return false;
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

uint DecompilerREV::IsConditionalInsn(cs_insn* insn) {
    switch (insn->id) {
    case X86_INS_JMP:
        return 1;
    case X86_INS_JNE:
        return 2;
    case X86_INS_JNO:
        return 2;
    case X86_INS_JNP:
        return 2;
    case X86_INS_JL:
        return 2;
    case X86_INS_JLE:
        return 2;
    case X86_INS_JG:
        return 2;
    case X86_INS_JGE:
        return 2;
    case X86_INS_JE:
        return 2;
    case X86_INS_JECXZ:
        return 2;
    case X86_INS_JCXZ:
        return 2;
    case X86_INS_JB:
        return 2;
    case X86_INS_JBE:
        return 2;
    case X86_INS_JA:
        return 2;
    case X86_INS_JAE:
        return 2;
    case X86_INS_JNS:
        return 2;
    case X86_INS_JO:
        return 2;
    case X86_INS_JP:
        return 2;
    case X86_INS_JRCXZ:
        return 2;
    case X86_INS_JS:
        return 2;
    default:
        break;
    }
    return 0;
}

uint DecompilerREV::CollectInsn(cs_insn* insn, struct Section *sections, uint index) {
    uint result = DECOMPILER_REV_OPERAND_TYPE_UNSET;
    switch (insn->id) {
    case X86_INS_JMP:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNO:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNP:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JL:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JLE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JG:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JGE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JECXZ:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JCXZ:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JB:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JBE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JA:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JAE:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNS:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JO:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JP:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JRCXZ:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JS:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_CALL:
        CollectOperands(insn, DECOMPILER_REV_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_REV_OPERAND_TYPE_FUNCTION;
        break;
    default:
        return result;
    }
    return result;
}

void DecompilerREV::CollectOperands(cs_insn* insn, int operand_type, struct Section *sections, uint index) {
    uint64_t address = X86_REL_ADDR(*insn);
    if (IsVisited(sections[index].visited, address) == false && address < sections[index].data_size) {
        sections[index].visited[address] = DECOMPILER_REV_VISITED_QUEUED;
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

bool DecompilerREV::IsFunction(map<uint64_t, uint> &addresses, uint64_t address){
    if (addresses.find(address) == addresses.end()){
        return false;
    }
    if (addresses.find(address)->second != DECOMPILER_REV_OPERAND_TYPE_FUNCTION){
        return false;
    }
    return true;
}

bool DecompilerREV::IsBlock(map<uint64_t, uint> &addresses, uint64_t address){
    if (addresses.find(address) == addresses.end()){
        return false;
    }
    if (addresses.find(address)->second == DECOMPILER_REV_OPERAND_TYPE_BLOCK ||
        addresses.find(address)->second == DECOMPILER_REV_OPERAND_TYPE_FUNCTION){
        return true;
    }
    return false;
}

void DecompilerREV::FreeTraits(uint index){
    if (sections[index].traits != NULL){
        for (int i = 0; i < sections[index].ntraits; i++){
            if (sections[index].traits[i]->bytes != NULL){
                free(sections[index].traits[i]->bytes);
            }
            if (sections[index].traits[i]->trait != NULL){
                free(sections[index].traits[i]->trait);
            }
            if (sections[index].traits[i] != NULL){
                free(sections[index].traits[i]);
            }
        }
        free(sections[index].traits);
    }
    sections[index].ntraits = 0;
}

DecompilerREV::~DecompilerREV() {
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++) {
        FreeTraits(i);
    }
}
