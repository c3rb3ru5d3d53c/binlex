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
#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif
#include <math.h>
#include <capstone/capstone.h>
#include "json.h"
#include "decompiler.h"

// Very WIP Multi-Threaded Recursive Decompiler

using namespace std;
using namespace binlex;
using json = nlohmann::json;
#ifndef _WIN32
static pthread_mutex_t DECOMPILER_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#else
CRITICAL_SECTION csDecompiler;
#endif

//from https://github.com/capstone-engine/capstone/blob/master/include/capstone/x86.h

#define X86_REL_ADDR(insn) (((insn).detail->x86.operands[0].type == X86_OP_IMM) \
	? (uint64_t)((insn).detail->x86.operands[0].imm) \
	: (((insn).address + (insn).size) + (uint64_t)(insn).detail->x86.disp))

Decompiler::Decompiler() {
    for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++) {
        sections[i].offset = 0;
        sections[i].traits = NULL;
        sections[i].ntraits = 0;
        sections[i].data = NULL;
        sections[i].data_size = 0;
        sections[i].threads = 1;
        sections[i].thread_cycles = 1;
        sections[i].thread_sleep = 500;
        sections[i].corpus = (char *)"default";
        sections[i].instructions = false;
        sections[i].arch_str = NULL;
    }
}

void Decompiler::SetFileSHA256(char *sha256, uint index){
    sections[index].file_sha256 = sha256;
}

void Decompiler::SetBLMode(char *mode, uint index){
    sections[index].blmode = mode;
}

void Decompiler::AppendTrait(struct Trait *trait, struct Section *sections, uint index){
    #if defined(__linux__) || defined(__APPLE__)
    pthread_mutex_lock(&DECOMPILER_MUTEX);
    #else
    EnterCriticalSection(&csDecompiler);
    #endif
    #if defined(__linux__) || defined(__APPLE__)
    sections[index].traits = (struct Trait **)realloc(sections[index].traits, sizeof(struct Trait *) * sections[index].ntraits + 1);
    #else
    if (sections[index].ntraits % 1024 == 0) {
        if (sections[index].ntraits == 0) {
            sections[index].traits = (struct Trait**)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(void*) * 1024);
        }
        else {
            sections[index].traits = (struct Trait**)HeapReAlloc(GetProcessHeap(), NULL, sections[index].traits, sizeof(void*) * (sections[index].ntraits + 1024));
        }
    }
    #endif
    if (sections[index].traits == NULL){
        fprintf(stderr, "[x] trait realloc failed\n");
        exit(1);
    }
    sections[index].traits[sections[index].ntraits] = (struct Trait *)malloc(sizeof(struct Trait));
    if (sections[index].traits[sections[index].ntraits] == NULL){
        fprintf(stderr, "[x] trait malloc failed\n");
        exit(1);
    }

    char *type = (char *)malloc(strlen(trait->type)+1);
    if (type == NULL){
        fprintf(stderr, "[x] trait malloc failed\n");
        exit(1);
    }
    memset(type, 0, strlen(trait->type)+1);
    if (memcpy(type, trait->type, strlen(trait->type)) == NULL){
        fprintf(stderr, "[x] trait memcpy failed\n");
        exit(1);
    }
    trait->type = type;

    trait->trait = (char *)malloc(strlen(trait->tmp_trait.c_str())+1);
    if (trait->trait == NULL){
        fprintf(stderr, "[x] trait malloc failed\n");
        exit(1);
    }
    memset(trait->trait, 0, strlen(trait->tmp_trait.c_str())+1);
    if (memcpy(trait->trait, trait->tmp_trait.c_str(), strlen(trait->tmp_trait.c_str())) == NULL){
        fprintf(stderr, "[x] trait memcpy failed\n");
        exit(1);
    }
    trait->bytes = (char *)malloc(strlen(trait->tmp_bytes.c_str())+1);
    if (trait->bytes == NULL){
        fprintf(stderr, "[x] trait malloc failed\n");
        exit(1);
    }
    memset(trait->bytes, 0, strlen(trait->tmp_bytes.c_str())+1);
    if (memcpy(trait->bytes, trait->tmp_bytes.c_str(), strlen(trait->tmp_bytes.c_str())) == NULL){
        fprintf(stderr, "[x] trait memcpy failed\n");
        exit(1);
    }
    if (memcpy(sections[index].traits[sections[index].ntraits], trait, sizeof(struct Trait)) == NULL){
        fprintf(stderr, "[x] trait memcpy failed\n");
        exit(1);
    }
    sections[index].ntraits++;
    trait->trait = (char *)trait->tmp_trait.c_str();
    trait->bytes = (char *)trait->tmp_bytes.c_str();
    #if defined(__linux__) || defined(__APPLE__)
    pthread_mutex_unlock(&DECOMPILER_MUTEX);
    #else
    LeaveCriticalSection(&csDecompiler);
    #endif
}

bool Decompiler::Setup(cs_arch arch, cs_mode mode, uint index){
    sections[index].arch = arch;
    sections[index].mode = mode;
    if (arch == CS_ARCH_X86 && mode == CS_MODE_32){
        sections[index].arch_str = (char *)"x86";
    }
    if (arch == CS_ARCH_X86 && mode == CS_MODE_64){
        sections[index].arch_str = (char *)"x86_64";
    }
    return true;
}

void Decompiler::SetThreads(uint threads, uint thread_cycles, uint thread_sleep, uint index){
    sections[index].threads = threads;
    sections[index].thread_cycles = thread_cycles;
    sections[index].thread_sleep = thread_sleep;
}

void Decompiler::SetCorpus(char *corpus, uint index){
    sections[index].corpus = corpus;
}

void Decompiler::SetInstructions(bool instructions, uint index){
    sections[index].instructions = instructions;
}

string Decompiler::GetTrait(struct Trait *trait, bool pretty){
    json data;
    data["type"] = trait->type;
    data["corpus"] = trait->corpus;
    data["file_sha256"] = trait->file_sha256;
    data["mode"] = trait->blmode;
    data["architecture"] = trait->architecture;
    data["bytes"] = trait->bytes;
    data["trait"] = trait->trait;
    data["edges"] = trait->edges;
    data["blocks"] = trait->blocks;
    data["instructions"] = trait->instructions;
    data["size"] = trait->size;
    data["offset"] = trait->offset;
    data["bytes_entropy"] = trait->bytes_entropy;
    data["bytes_sha256"] = trait->bytes_sha256;
    data["trait_sha256"] = trait->trait_sha256;
    data["trait_entropy"] = trait->trait_entropy;
    data["invalid_instructions"] = trait->invalid_instructions;
    data["cyclomatic_complexity"] = trait->cyclomatic_complexity;
    data["average_instructions_per_block"] = trait->average_instructions_per_block;
    if (pretty == true){
        return data.dump(4);
    }
    return data.dump();
}

void Decompiler::PrintTraits(bool pretty){
    for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++){
        if (sections[i].traits != NULL){
            for (int j = 0; j < sections[i].ntraits; j++){
                sections[i].traits[j]->corpus = sections[i].corpus;
                sections[i].traits[j]->file_sha256 = sections[i].file_sha256;
                sections[i].traits[j]->blmode = sections[i].blmode;
                cout << GetTrait(sections[i].traits[j], pretty) << endl;
            }
        }
    }
}

string Decompiler::GetTraits(bool pretty){
    stringstream ss;
    string sep = "";
    ss << '[';
    for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++){
        if (sections[i].traits != NULL){
            for (int j = 0; j < sections[i].ntraits; j++){
                sections[i].traits[j]->corpus = sections[i].corpus;
                sections[i].traits[j]->file_sha256 = sections[i].file_sha256;
                sections[i].traits[j]->blmode = sections[i].blmode;
                ss << sep << GetTrait(sections[i].traits[j], pretty);
                sep = ",";
            }
        }
    }
    ss << ']';
    return ss.str();
}

void Decompiler::WriteTraits(char *file_path, bool pretty){
    FILE *fd = fopen(file_path, "w");
    stringstream traits;
    for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++){
        if (sections[i].traits != NULL){
            for (int j = 0; j < sections[i].ntraits; j++){
                sections[i].traits[j]->corpus = sections[i].corpus;
                sections[i].traits[j]->file_sha256 = sections[i].file_sha256;
                sections[i].traits[j]->blmode = sections[i].blmode;
                traits << GetTrait(sections[i].traits[j], pretty) << endl;
            }
        }
    }
    fwrite(traits.str().c_str(), sizeof(char), traits.str().length(), fd);
    fclose(fd);
}

void * Decompiler::DecompileWorker(void *args) {

    worker myself;
    worker_args *pArgs = (worker_args *)args;
    uint index = pArgs->index;
    struct Section *sections = (struct Section *)pArgs->sections;

    struct Trait b_trait;
    struct Trait f_trait;
    struct Trait i_trait;

    i_trait.type = (char *)"instruction";
    i_trait.architecture = sections[index].arch_str;
    ClearTrait(&i_trait);
    b_trait.type = (char *)"block";
    b_trait.architecture = sections[index].arch_str;
    ClearTrait(&b_trait);
    f_trait.type = (char *)"function";
    f_trait.architecture = sections[index].arch_str;
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
        pthread_mutex_lock(&DECOMPILER_MUTEX);
        #else
        EnterCriticalSection(&csDecompiler);
        #endif
        if (!sections[index].discovered.empty()){
            address = sections[index].discovered.front();
            sections[index].discovered.pop();
            sections[index].visited[address] = DECOMPILER_VISITED_ANALYZED;
        } else {
            #if defined(__linux__) || defined(__APPLE__)
            pthread_mutex_unlock(&DECOMPILER_MUTEX);
            #else
            LeaveCriticalSection(&csDecompiler);
            #endif
            thread_cycles++;
            if (thread_cycles == sections[index].thread_cycles){
                break;
            }
            #ifndef _WIN32
            usleep(sections[index].thread_sleep * 1000);
            #else
            Sleep(sections[index].thread_sleep);
            #endif
            continue;
        }
        sections[index].coverage.insert(address);
        #if defined(__linux__) || defined(__APPLE__)
        pthread_mutex_unlock(&DECOMPILER_MUTEX);
        #else
        LeaveCriticalSection(&csDecompiler);
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

            if (sections[index].instructions == true){
                if (result == true){
                    i_trait.tmp_bytes = HexdumpBE(insn->bytes, insn->size);
                    i_trait.size = GetByteSize(i_trait.tmp_bytes);
                    i_trait.offset = sections[index].offset + myself.pc - i_trait.size;
                    i_trait.tmp_trait = WildcardInsn(insn);
                    i_trait.instructions = 1;
                    i_trait.edges = IsConditionalInsn(insn);
                    AppendTrait(&i_trait, sections, index);
                    ClearTrait(&i_trait);
                } else {
                    i_trait.instructions = 1;
                    i_trait.invalid_instructions = 1;
                    i_trait.tmp_bytes = i_trait.tmp_bytes + HexdumpBE(myself.code, 1);
                    i_trait.tmp_trait = i_trait.tmp_trait + Wildcards(1);
                    AppendTrait(&i_trait, sections, index);
                    ClearTrait(&i_trait);
                }
            }

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
            pthread_mutex_lock(&DECOMPILER_MUTEX);
            #else
            EnterCriticalSection(&csDecompiler);
            #endif

            if (result == true){
                sections[index].coverage.insert(myself.pc);
            } else {
                sections[index].coverage.insert(myself.pc+1);
            }
            CollectInsn(insn, sections, index);

            //printf("address=0x%" PRIx64 ",block=%d,function=%d,queue=%ld,instruction=%s\t%s\n", insn->address,IsBlock(sections[index].addresses, insn->address), IsFunction(sections[index].addresses, insn->address), sections[index].discovered.size(), insn->mnemonic, insn->op_str);

            #if defined(__linux__) || defined(__APPLE__)
            pthread_mutex_unlock(&DECOMPILER_MUTEX);
            #else
            LeaveCriticalSection(&csDecompiler);
            #endif
            if (block == true && IsConditionalInsn(insn) > 0){
                b_trait.tmp_trait = TrimRight(b_trait.tmp_trait);
                b_trait.tmp_bytes = TrimRight(b_trait.tmp_bytes);
                b_trait.size = GetByteSize(b_trait.tmp_bytes);
                b_trait.offset = sections[index].offset + myself.pc - b_trait.size;
                AppendTrait(&b_trait, sections, index);
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
                AppendTrait(&b_trait, sections, index);
                ClearTrait(&b_trait);
            }

            if (function == true && IsEndInsn(insn) == true){
                f_trait.tmp_trait = TrimRight(f_trait.tmp_trait);
                f_trait.tmp_bytes = TrimRight(f_trait.tmp_bytes);
                f_trait.size = GetByteSize(f_trait.tmp_bytes);
                f_trait.offset = sections[index].offset + myself.pc - f_trait.size;
                AppendTrait(&f_trait, sections, index);
                ClearTrait(&f_trait);
                break;
            }
        }
    }
    cs_free(insn, 1);
    cs_close(&myself.handle);
    return NULL;
}

void * Decompiler::TraitWorker(void *args){
    struct Trait *trait = (struct Trait *)args;
    if (trait->blocks == 0 &&
        (strcmp(trait->type, "function") == 0 ||
        strcmp(trait->type, "block") == 0)){
        trait->blocks++;
    }
    trait->bytes_entropy = Entropy(string(trait->bytes));
    trait->trait_entropy = Entropy(string(trait->trait));
    string bytes_sha256 = SHA256(trait->bytes, strlen(trait->bytes));
    trait->bytes_sha256 = (char *)malloc(bytes_sha256.length()+1);
    memset(trait->bytes_sha256, 0, bytes_sha256.length()+1);
    memcpy(trait->bytes_sha256, bytes_sha256.c_str(), bytes_sha256.length());
    string trait_sha256 = SHA256(trait->trait, strlen(trait->trait));
    trait->trait_sha256 = (char *)malloc(trait_sha256.length()+1);
    memset(trait->trait_sha256, 0, trait_sha256.length()+1);
    memcpy(trait->trait_sha256, trait_sha256.c_str(), trait_sha256.length());
    if (strcmp(trait->type, (char *)"block") == 0){
        trait->cyclomatic_complexity = trait->edges - 1 + 2;
        trait->average_instructions_per_block = trait->instructions / 1;
    }
    if (strcmp(trait->type, (char *)"function") == 0){
        trait->cyclomatic_complexity = trait->edges - trait->blocks + 2;
        trait->average_instructions_per_block = trait->instructions / trait->blocks;
    }
    return NULL;

}

void Decompiler::ClearTrait(struct Trait *trait){
    trait->tmp_bytes.clear();
    trait->edges = 0;
    trait->instructions = 0;
    trait->blocks = 0;
    trait->offset = 0;
    trait->size = 0;
    trait->invalid_instructions = 0;
    trait->tmp_trait.clear();
    trait->trait = NULL;
    trait->bytes_sha256 = NULL;
}

void Decompiler::AppendQueue(set<uint64_t> &addresses, uint operand_type, uint index){
    for (auto it = addresses.begin(); it != addresses.end(); ++it){
        uint64_t tmp_addr = *it;
        sections[index].discovered.push(tmp_addr);
        sections[index].visited[tmp_addr] = DECOMPILER_VISITED_QUEUED;
        sections[index].addresses[tmp_addr] = operand_type;
    }
}

void Decompiler::Decompile(void* data, size_t data_size, size_t offset, uint index) {
    sections[index].data = data;
    sections[index].data_size = data_size;

    sections[index].discovered.push(0);
    sections[index].addresses[0] = DECOMPILER_OPERAND_TYPE_FUNCTION;
    sections[index].visited[0] = DECOMPILER_VISITED_QUEUED;

    worker_args *args = (worker_args *)malloc(sizeof(worker_args));
    args->index = index;
    args->sections = &sections;

    #if defined(__linux__) || defined(__APPLE__)
    pthread_t threads[sections[index].threads];
    pthread_attr_t thread_attribs[sections[index].threads];
    #else
    InitializeCriticalSection(&csDecompiler);
    DWORD dwThreads = sections[index].threads;
    HANDLE* hThreads = (HANDLE*)malloc(sizeof(HANDLE) * dwThreads);
    DWORD dwThreadId;
    #endif

    while (true){
        for (int i = 0; i < sections[index].threads; i++){
            #if defined(__linux__) || defined(__APPLE__)
            pthread_attr_init(&thread_attribs[i]);
            pthread_attr_setdetachstate(&thread_attribs[i], PTHREAD_CREATE_JOINABLE);
            pthread_create(&threads[i], NULL, DecompileWorker, args);
            #else
            hThreads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DecompileWorker, args, 0, &dwThreadId);
            #endif
        }
        for (int i = 0; i < sections[index].threads; i++){
            #if defined(__linux__) || defined(__APPLE__)
            pthread_join(threads[i], NULL);
            #else
            WaitForMultipleObjects(sections[index].threads, hThreads, TRUE, INFINITE);
            #endif
        }
        if (sections[index].discovered.empty()){
            uint64_t tmp_addr = MaxAddress(sections[index].coverage);
            if (tmp_addr < sections[index].data_size){
                sections[index].discovered.push(tmp_addr);
                sections[index].addresses[tmp_addr] = DECOMPILER_OPERAND_TYPE_FUNCTION;
                sections[index].visited[tmp_addr] = DECOMPILER_VISITED_QUEUED;
                continue;
            }
            break;
        }
    }
    for (int i = 0; i < sections[index].ntraits; i += sections[index].threads) {
        for (int j = 0; j < sections[index].threads; j++) {
            #if defined(__linux__) || defined(__APPLE__)
            if (i + j < sections[index].ntraits) {
                pthread_attr_init(&thread_attribs[j]);
                pthread_attr_setdetachstate(&thread_attribs[j], PTHREAD_CREATE_JOINABLE);
                pthread_create(&threads[j], NULL, TraitWorker, (void*)sections[index].traits[i + j]);
            }
            else {
                threads[j] = NULL;
            }
            #else
            if (i + j < sections[index].ntraits) {
                hThreads[j] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TraitWorker, (void*)sections[index].traits[i + j], 0, &dwThreadId);
            }
            else {
                hThreads[j] = INVALID_HANDLE_VALUE;
            }
            #endif
            }
        #if defined(__linux__) || defined(__APPLE__)
        for (int j = 0; j < sections[index].threads; j++) {
            if (threads[j] != NULL) {
                pthread_join(threads[j], NULL);
            }
        }
        #else
        WaitForMultipleObjects(sections[index].threads, hThreads, TRUE, INFINITE);
        #endif
    }
    #ifdef _WIN32
    free(hThreads);
    #endif
    free(args);
}

string Decompiler::WildcardInsn(cs_insn *insn){
    string bytes = HexdumpBE(insn->bytes, insn->size);
    string trait = bytes;
    for (int j = 0; j < insn->detail->x86.op_count; j++){
        cs_x86_op operand = insn->detail->x86.operands[j];
        switch(operand.type){
            case X86_OP_MEM:
                {
                    if (operand.mem.disp != 0){
                        trait = WildcardTrait(HexdumpBE(insn->bytes, insn->size), HexdumpMemDisp(operand.mem.disp));
                    }
                    break;
                }
            default:
                break;
        }
    }
    return TrimRight(trait);
}

bool Decompiler::IsVisited(map<uint64_t, int> &visited, uint64_t address) {
    return visited.find(address) != visited.end();
}

bool Decompiler::IsWildcardInsn(cs_insn *insn){
    switch (insn->id) {
        case X86_INS_NOP:
            return true;
        default:
            break;
    }
    return false;
}

bool Decompiler::IsEndInsn(cs_insn *insn) {
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

uint Decompiler::IsConditionalInsn(cs_insn* insn) {
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

uint Decompiler::CollectInsn(cs_insn* insn, struct Section *sections, uint index) {
    uint result = DECOMPILER_OPERAND_TYPE_UNSET;
    switch (insn->id) {
    case X86_INS_JMP:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNE:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNO:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNP:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JL:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JLE:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JG:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JGE:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JE:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JECXZ:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JCXZ:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JB:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JBE:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JA:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JAE:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JNS:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JO:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JP:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JRCXZ:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_JS:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_BLOCK, sections, index);
        result = DECOMPILER_OPERAND_TYPE_BLOCK;
        break;
    case X86_INS_CALL:
        CollectOperands(insn, DECOMPILER_OPERAND_TYPE_FUNCTION, sections, index);
        result = DECOMPILER_OPERAND_TYPE_FUNCTION;
        break;
    default:
        return result;
    }
    return result;
}

void Decompiler::CollectOperands(cs_insn* insn, int operand_type, struct Section *sections, uint index) {
    uint64_t address = X86_REL_ADDR(*insn);
    if (IsVisited(sections[index].visited, address) == false && address < sections[index].data_size) {
        sections[index].visited[address] = DECOMPILER_VISITED_QUEUED;
        switch(operand_type){
            case DECOMPILER_OPERAND_TYPE_BLOCK:
                sections[index].addresses[address] = DECOMPILER_OPERAND_TYPE_BLOCK;
                sections[index].discovered.push(address);
                break;
            case DECOMPILER_OPERAND_TYPE_FUNCTION:
                sections[index].addresses[address] = DECOMPILER_OPERAND_TYPE_FUNCTION;
                sections[index].discovered.push(address);
                break;
            default:
                break;
        }
    }
}

uint64_t Decompiler::MaxAddress(set<uint64_t> coverage){
    uint64_t max_element;
    if (!coverage.empty()){
        max_element = *(coverage.rbegin());
    }
    return max_element;
}

bool Decompiler::IsAddress(map<uint64_t, uint> &addresses, uint64_t address, uint index){
    if (addresses.find(address) == addresses.end()){
        return false;
    }
    return true;
}

bool Decompiler::IsFunction(map<uint64_t, uint> &addresses, uint64_t address){
    if (addresses.find(address) == addresses.end()){
        return false;
    }
    if (addresses.find(address)->second != DECOMPILER_OPERAND_TYPE_FUNCTION){
        return false;
    }
    return true;
}

bool Decompiler::IsBlock(map<uint64_t, uint> &addresses, uint64_t address){
    if (addresses.find(address) == addresses.end()){
        return false;
    }
    if (addresses.find(address)->second == DECOMPILER_OPERAND_TYPE_BLOCK ||
        addresses.find(address)->second == DECOMPILER_OPERAND_TYPE_FUNCTION){
        return true;
    }
    return false;
}

void Decompiler::FreeTraits(uint index){
    if (sections[index].traits != NULL){
        for (int i = 0; i < sections[index].ntraits; i++){
            if (sections[index].traits[i]->type != NULL){
                free(sections[index].traits[i]->type);
            }
            if (sections[index].traits[i]->trait_sha256 != NULL){
                free(sections[index].traits[i]->trait_sha256);
            }
            if (sections[index].traits[i]->bytes_sha256 != NULL){
                free(sections[index].traits[i]->bytes_sha256);
            }
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

Decompiler::~Decompiler() {
    for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++) {
        FreeTraits(i);
    }
}
