#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <iomanip>
#include <math.h>

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

#include <capstone/capstone.h>
#include "json.h"
#include "decompiler.h"

// Very WIP Multi-Threaded Recursive Decompiler

using namespace binlex;
using json = nlohmann::json;

cs_arch Decompiler::arch;
cs_mode Decompiler::mode;

//from https://github.com/capstone-engine/capstone/blob/master/include/capstone/x86.h

#define X86_REL_ADDR(insn) (((insn).detail->x86.operands[0].type == X86_OP_IMM) \
	? (uint64_t)((insn).detail->x86.operands[0].imm) \
	: (((insn).address + (insn).size) + (uint64_t)(insn).detail->x86.disp))

Decompiler::Decompiler(const binlex::File &firef) : DecompilerBase(firef) {
    for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++) {
        sections[i].offset = 0;
        sections[i].data = NULL;
        sections[i].data_size = 0;
    }
}

void Decompiler::AppendTrait(struct Trait *trait, struct Section *sections, uint index){
    struct Trait new_elem_trait = *trait; //copy the stuff populated in the caller, TODO: more cleanup required to not copy anything.

    new_elem_trait.type = (char *)malloc(strlen(trait->type) + 1);
    if (new_elem_trait.type == NULL){
        PRINT_ERROR_AND_EXIT("[x] trait malloc failed\n");
    }
    memset(new_elem_trait.type, 0, strlen(trait->type) + 1);
    if (memcpy(new_elem_trait.type, trait->type, strlen(trait->type)) == NULL){
        PRINT_ERROR_AND_EXIT("[x] trait memcpy failed\n");
    }

    new_elem_trait.trait = (char *)malloc(strlen(trait->tmp_trait.c_str()) + 1);
    if (new_elem_trait.trait == NULL){
        PRINT_ERROR_AND_EXIT("[x] trait malloc failed\n");
    }
    memset(new_elem_trait.trait, 0, strlen(trait->tmp_trait.c_str()) + 1);
    if (memcpy(new_elem_trait.trait, trait->tmp_trait.c_str(), strlen(trait->tmp_trait.c_str())) == NULL){
        PRINT_ERROR_AND_EXIT("[x] trait memcpy failed\n");
    }
    new_elem_trait.bytes = (char *)malloc(strlen(trait->tmp_bytes.c_str()) + 1);
    if (new_elem_trait.bytes == NULL){
        PRINT_ERROR_AND_EXIT("[x] trait malloc failed\n");
    }
    memset(new_elem_trait.bytes, 0, strlen(trait->tmp_bytes.c_str()) + 1);
    if (memcpy(new_elem_trait.bytes, trait->tmp_bytes.c_str(), strlen(trait->tmp_bytes.c_str())) == NULL){
        PRINT_ERROR_AND_EXIT("[x] trait memcpy failed\n");
    }
    sections[index].traits.push_back(new_elem_trait);
 }

bool Decompiler::Setup(cs_arch architecture, cs_mode mode_type) {
    arch = architecture;
    mode = mode_type;
    return true;
}

json Decompiler::GetTrait(struct Trait &trait){
    json data;
    data["type"] = trait.type;
    data["corpus"] = g_args.options.corpus;
    data["tags"] = g_args.options.tags;
    data["mode"] = g_args.options.mode;
    data["bytes"] = trait.bytes;
    data["trait"] = trait.trait;
    data["edges"] = trait.edges;
    data["blocks"] = trait.blocks;
    data["instructions"] = trait.instructions;
    data["size"] = trait.size;
    data["offset"] = trait.offset;
    data["bytes_entropy"] = trait.bytes_entropy;
    data["bytes_sha256"] = &trait.bytes_sha256[0];
    data["trait_sha256"] = &trait.trait_sha256[0];
    data["trait_entropy"] = trait.trait_entropy;
    data["invalid_instructions"] = trait.invalid_instructions;
    data["cyclomatic_complexity"] = trait.cyclomatic_complexity;
    data["average_instructions_per_block"] = trait.average_instructions_per_block;
    return data;
}

vector<json> Decompiler::GetTraits(){
    vector<json> traitsjson;
    for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++){
        if (sections[i].data != NULL){
            for (int j = 0; j < sections[i].traits.size(); j++){
                json jdata(GetTrait(sections[i].traits[j]));
                traitsjson.push_back(jdata);
            }
        }
    }
    return traitsjson;
}

void * Decompiler::CreateTraitsForSection(uint index) {
    worker myself;

    struct Trait b_trait;
    struct Trait f_trait;
    struct Trait i_trait;

    PRINT_DEBUG("----------\nHandling section %u\n----------\n", index);

    i_trait.type = (char *)"instruction";
    //i_trait.architecture = sections[index].arch_str;
    ClearTrait(&i_trait);
    b_trait.type = (char *)"block";
    //b_trait.architecture = sections[index].arch_str;
    ClearTrait(&b_trait);
    f_trait.type = (char *)"function";
    //f_trait.architecture = sections[index].arch_str;
    ClearTrait(&f_trait);

    myself.error = cs_open(arch, mode, &myself.handle);
    if (myself.error != CS_ERR_OK) {
        return NULL;
    }
    myself.error = cs_option(myself.handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (myself.error != CS_ERR_OK) {
        return NULL;
    }

    cs_insn *insn = cs_malloc(myself.handle);
    while (!sections[index].discovered.empty()){

        uint64_t tmp_addr = 0;
        uint64_t address = 0;

        PRINT_DEBUG("discovered size = %u\n", (uint32_t)sections[index].discovered.size());
        PRINT_DEBUG("visited size = %u\n",    (uint32_t)sections[index].visited.size());
        PRINT_DEBUG("coverage size = %u\n",   (uint32_t)sections[index].coverage.size());
        PRINT_DEBUG("addresses size = %u\n",  (uint32_t)sections[index].addresses.size());

        address = sections[index].discovered.front();
        sections[index].discovered.pop();
        sections[index].visited[address] = DECOMPILER_VISITED_ANALYZED;

        sections[index].coverage.insert(address);

        myself.pc = address;
        myself.code = (uint8_t *)((uint8_t *)sections[index].data + address);
        myself.code_size = sections[index].data_size + address;

        bool block = IsBlock(sections[index].addresses, address);
        bool function = IsFunction(sections[index].addresses, address);
        uint suspicious_instructions = 0;

        while(true) {
            uint edges = 0;

            if (myself.pc >= sections[index].data_size) {
                break;
            }

            bool result = cs_disasm_iter(myself.handle, &myself.code, &myself.code_size, &myself.pc, insn);

            if (result != true){
                // Error with disassembly, not a valid basic block,
                PRINT_DEBUG("*** Decompile error rejected block: 0x%" PRIx64 "\n", myself.pc);
                ClearTrait(&b_trait);
                ClearTrait(&i_trait);
                ClearTrait(&f_trait);
                myself.code = (uint8_t *)((uint8_t *)myself.code + 1);
                myself.code_size +=1;
                myself.pc +=1;
                sections[index].coverage.insert(myself.pc);
                break;

            }

            sections[index].coverage.insert(myself.pc);

            // Check for suspicious instructions and count them
            if (IsNopInsn(insn) || IsSemanticNopInsn(insn) || IsTrapInsn(insn) || IsPrivInsn(insn) ){
                suspicious_instructions += 1;
            }

            // If there are too many suspicious instructions in the bb discard it
            // TODO: Make this configurable as an argument
            if (suspicious_instructions > 2){
                PRINT_DEBUG("*** Suspicious instructions rejected block: 0x%" PRIx64 "\n", insn->address);
                ClearTrait(&b_trait);
                ClearTrait(&i_trait);
                ClearTrait(&f_trait);
                break;
            }

            b_trait.instructions++;
            f_trait.instructions++;

            if (g_args.options.instructions == true){
                i_trait.tmp_bytes = HexdumpBE(insn->bytes, insn->size);
                i_trait.size = GetByteSize(i_trait.tmp_bytes);
                i_trait.offset = sections[index].offset + myself.pc - i_trait.size;
                i_trait.tmp_trait = WildcardInsn(insn);
                i_trait.instructions = 1;
                i_trait.edges = IsConditionalInsn(insn);
                AppendTrait(&i_trait, sections, index);
                ClearTrait(&i_trait);
            }

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



            CollectInsn(insn, sections, index);

            PRINT_DEBUG("address=0%" PRIx64 ",block=%d,function=%d,queue=%ld,instruction=%s\t%s\n", insn->address,IsBlock(sections[index].addresses, insn->address), IsFunction(sections[index].addresses, insn->address), sections[index].discovered.size(), insn->mnemonic, insn->op_str);

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

void * Decompiler::FinalizeTrait(struct Trait &trait){
    if (trait.blocks == 0 &&
        (strcmp(trait.type, "function") == 0 ||
        strcmp(trait.type, "block") == 0)){
        trait.blocks++;
    }
    trait.bytes_entropy = Entropy(string(trait.bytes));
    trait.trait_entropy = Entropy(string(trait.trait));
    memcpy(&trait.bytes_sha256[0], SHA256(trait.bytes).c_str(), SHA256_PRINTABLE_SIZE);
    memcpy(&trait.trait_sha256[0], SHA256(trait.trait).c_str(), SHA256_PRINTABLE_SIZE);
    if (strcmp(trait.type, (char *)"block") == 0){
        trait.cyclomatic_complexity = trait.edges - 1 + 2;
        trait.average_instructions_per_block = trait.instructions / 1;
    }
    if (strcmp(trait.type, (char *)"function") == 0){
        trait.cyclomatic_complexity = trait.edges - trait.blocks + 2;
        trait.average_instructions_per_block = trait.instructions / trait.blocks;
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
    memset(&trait->bytes_sha256[0], 0, SHA256_PRINTABLE_SIZE);
    memset(&trait->trait_sha256[0], 0, SHA256_PRINTABLE_SIZE);
}

void Decompiler::AppendQueue(set<uint64_t> &addresses, uint operand_type, uint index){
    PRINT_DEBUG("List of queued addresses for section %u correponding to found functions: ", index);
    for (auto it = addresses.begin(); it != addresses.end(); ++it){
        uint64_t tmp_addr = *it;
        sections[index].discovered.push(tmp_addr);
        sections[index].visited[tmp_addr] = DECOMPILER_VISITED_QUEUED;
        sections[index].addresses[tmp_addr] = operand_type;
        PRINT_DEBUG("0x%" PRIu64 " ", tmp_addr);
    }
    PRINT_DEBUG("\n");
}

void Decompiler::LinearDisassemble(void* data, size_t data_size, size_t offset, uint index) {
    // This function is intended to perform a preliminary quick linear disassembly pass of the section
    // and initially populate the discovered queue with addressed that may not be found via recursive disassembly.
    //
    // TODO: This algorithm is garbage and creates a lot of false positives, it should be replaced with a proper
    // linear pass that can differentiate data and code.
    // See research linked here: https://github.com/c3rb3ru5d3d53c/binlex/issues/42#issuecomment-1110479885
    //
    // * The Algorithm *
    // - Disassemble each instruction sequentially
    // - Track the state of the disassembly (valid / invalid)
    // - The state is set to invalid for nops, traps, privileged instructions, and errors
    // - When a jmp (conditional or unconditional) is encountered if the state is valid begin counting valid “blocks”
    // - When three consecutive blocks are found push the jmp addresses onto the queue
    // - When a jmp (conditional or unconditional) is encountered if the state is invalid reset to valid and begin tracking blocks
    //
    // * Weaknesses *
    // - We don’t collect calls (these are assumed to be collected in the recursive disassembler)
    // - We don’t reset the state on ret or call instructions possibly missing some valid blocks
    // - We don’t collect the next address after a jmp (next block) missing some valid blocks
    // - Even with the filtering we will still add some number of addresses that are from invalid jmp institutions

    csh cs_dis;

    PRINT_DEBUG("LinearDisassemble: Started at offset = 0x%x data_size = %d bytes\n", offset, data_size);

    if(cs_open(arch, mode, &cs_dis) != CS_ERR_OK) {
        PRINT_ERROR_AND_EXIT("[x] LinearDisassembly failed to init capstone\n");
    }

    if (cs_option(cs_dis, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        PRINT_ERROR_AND_EXIT("[x] LinearDisassembly failed to set capstone options\n");
    }

    cs_insn *cs_ins = cs_malloc(cs_dis);
    uint64_t pc = offset;
    const uint8_t *code = (uint8_t *)((uint8_t *)data);
    size_t code_size = data_size + pc;
    // Track our state, assume we start in a valid bb
    bool valid_block = true;
    uint64_t valid_block_count = 1;
    // Save the last two valid jmp addresses
    // These can be pushed once we confirm three valid blocks
    uint64_t jmp_address_1 = 0;
    uint64_t jmp_address_2 = 0;

    while(pc < code_size){
        if (!cs_disasm_iter(cs_dis, &code, &code_size, &pc, cs_ins)){
            PRINT_DEBUG("LinearDisassemble: 0x%x: Disassemble ERROR\n", pc);
            // If the disassembly fails skip the byte and continue
            pc += 1;
            code_size -= 1;
            code = (uint8_t *)((uint8_t *)code + 1);
            valid_block = false;
            valid_block_count = 0;
            continue;
        }
        PRINT_DEBUG("LinearDisassemble: 0x%x: %s\t%s\n", cs_ins->address, cs_ins->mnemonic, cs_ins->op_str);

        if (IsNopInsn(cs_ins) || IsSemanticNopInsn(cs_ins) || IsTrapInsn(cs_ins) || IsPrivInsn(cs_ins) ){
            PRINT_DEBUG("LinearDisassemble: Suspicious instruction at 0x%x\n", cs_ins->address);
            valid_block = false;
            valid_block_count = 0;
        }

        if(!cs_ins->size) {
            PRINT_DEBUG("LinearDisassemble: Invalid instruction size at 0x%x\n", cs_ins->address);
        }
        if (IsConditionalInsn(cs_ins)){
            if (valid_block){
                if (valid_block_count == 1) {
                    jmp_address_2 =  X86_REL_ADDR(*cs_ins);
                }
                else if (valid_block_count = 2) {
                    PRINT_DEBUG("LinearDisassemble: Found three consecutive valid blocks adding jmp addresses");
                    AddDiscoveredBlock(jmp_address_1, sections, index);
                    AddDiscoveredBlock(jmp_address_2, sections, index);
                    CollectInsn(cs_ins, sections, index);
                }
                else{
                    CollectInsn(cs_ins, sections, index);
                }
                valid_block_count += 1;
            }
            else{
                // Reset block state and try again
                valid_block = true;
                valid_block_count = 1;
                jmp_address_1 = X86_REL_ADDR(*cs_ins);
            }
        }

    }

    cs_free(cs_ins, 1);

};

void Decompiler::Decompile(void* data, size_t data_size, size_t offset, uint index) {
    sections[index].offset  = offset;
    sections[index].data = data;
    sections[index].data_size = data_size;

    PRINT_DEBUG("Decompile: offset = 0x%x data_size = %" PRId64 " bytes\n", sections[index].offset, sections[index].data_size);
    PRINT_DATA("Section Data (up to 32 bytes)", sections[index].data, std::min((size_t)32, sections[index].data_size));

    // Run a linear disassemble on the data to populate the queue
    //TODO: enable when this is ready
    LinearDisassemble(data, data_size, offset, index);

    CreateTraitsForSection(index);

    for (size_t i = 0; i < sections[index].traits.size(); ++i) {
        FinalizeTrait(sections[index].traits[i]);
    }
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
                        trait = WildcardTrait(bytes, HexdumpBE(&operand.mem.disp, sizeof(uint64_t)));
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


bool Decompiler::IsNopInsn(cs_insn *ins)
{
    switch(ins->id) {
    case X86_INS_NOP:
    case X86_INS_FNOP:
        return true;
    default:
        return false;
    }
}

bool Decompiler::IsSemanticNopInsn(cs_insn *ins)
{
    cs_x86 *x86;

    /* XXX: to make this truly platform-independent, we need some real
     * semantic analysis, but for now checking known cases is sufficient */

    x86 = &ins->detail->x86;
    switch(ins->id) {
    case X86_INS_MOV:
        /* mov reg,reg */
        if((x86->op_count == 2)
             && (x86->operands[0].type == X86_OP_REG)
             && (x86->operands[1].type == X86_OP_REG)
             && (x86->operands[0].reg == x86->operands[1].reg)) {
            return true;
        }
        return false;
    case X86_INS_XCHG:
        /* xchg reg,reg */
        if((x86->op_count == 2)
             && (x86->operands[0].type == X86_OP_REG)
             && (x86->operands[1].type == X86_OP_REG)
             && (x86->operands[0].reg == x86->operands[1].reg)) {
            return true;
        }
        return false;
    case X86_INS_LEA:
        /* lea        reg,[reg + 0x0] */
        if((x86->op_count == 2)
             && (x86->operands[0].type == X86_OP_REG)
             && (x86->operands[1].type == X86_OP_MEM)
             && (x86->operands[1].mem.segment == X86_REG_INVALID)
             && (x86->operands[1].mem.base == x86->operands[0].reg)
             && (x86->operands[1].mem.index == X86_REG_INVALID)
             /* mem.scale is irrelevant since index is not used */
             && (x86->operands[1].mem.disp == 0)) {
            return true;
        }
        /* lea        reg,[reg + eiz*x + 0x0] */
        if((x86->op_count == 2)
             && (x86->operands[0].type == X86_OP_REG)
             && (x86->operands[1].type == X86_OP_MEM)
             && (x86->operands[1].mem.segment == X86_REG_INVALID)
             && (x86->operands[1].mem.base == x86->operands[0].reg)
             && (x86->operands[1].mem.index == X86_REG_EIZ)
             /* mem.scale is irrelevant since index is the zero-register */
             && (x86->operands[1].mem.disp == 0)) {
            return true;
        }
        return false;
    default:
        return false;
    }
}

bool Decompiler::IsTrapInsn(cs_insn *ins)
{
    switch(ins->id) {
    case X86_INS_INT3:
    case X86_INS_UD2:
    case X86_INS_INT1:
    case X86_INS_INTO:
        return true;
    default:
        return false;
    }
}

bool Decompiler::IsPrivInsn(cs_insn *ins)
{
    switch(ins->id) {
    case X86_INS_HLT:
    case X86_INS_IN:
    case X86_INS_INSB:
    case X86_INS_INSW:
    case X86_INS_INSD:
    case X86_INS_OUT:
    case X86_INS_OUTSB:
    case X86_INS_OUTSW:
    case X86_INS_OUTSD:
    case X86_INS_RDMSR:
    case X86_INS_WRMSR:
    case X86_INS_RDPMC:
    case X86_INS_RDTSC:
    case X86_INS_LGDT:
    case X86_INS_LLDT:
    case X86_INS_LTR:
    case X86_INS_LMSW:
    case X86_INS_CLTS:
    case X86_INS_INVD:
    case X86_INS_INVLPG:
    case X86_INS_WBINVD:
        return true;
    default:
        return false;
    }
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

void Decompiler::AddDiscoveredBlock(uint64_t address, struct Section *sections, uint index) {
    if (IsVisited(sections[index].visited, address) == false && address < sections[index].data_size) {
        sections[index].visited[address] = DECOMPILER_VISITED_QUEUED;
        sections[index].addresses[address] = DECOMPILER_OPERAND_TYPE_BLOCK;
        sections[index].discovered.push(address);
    }
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
    if (sections[index].data != NULL){
        for (int i = 0; i < sections[index].traits.size(); i++){
            if (sections[index].traits[i].type != NULL){
                free(sections[index].traits[i].type);
            }
            if (sections[index].traits[i].bytes != NULL){
                free(sections[index].traits[i].bytes);
            }
            if (sections[index].traits[i].trait != NULL){
                free(sections[index].traits[i].trait);
            }
        }
    }
    sections[index].traits.clear();
}

Decompiler::~Decompiler() {
    for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++) {
        FreeTraits(i);
    }
}
