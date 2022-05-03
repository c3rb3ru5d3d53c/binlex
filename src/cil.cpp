#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <assert.h>
#include <byteswap.h>
#include <ctype.h>
#include <capstone/capstone.h>
#include "common.h"
#include "cil.h"
#include "decompiler.h"
#include <unistd.h>
#include <vector>

using namespace std;
using namespace binlex;
using json = nlohmann::json;
#ifndef _WIN32
static pthread_mutex_t DECOMPILER_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#else
CRITICAL_SECTION csDecompiler;
#endif

CILDecompiler::CILDecompiler(){
    int type = CIL_DECOMPILER_TYPE_UNSET;
    for (int i = 0; i < CIL_DECOMPILER_MAX_SECTIONS; i++){
        sections[i].function_traits = NULL;
        sections[i].block_traits = NULL;
        sections[i].offset = 0;
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
    //Maps give us O(nlogn) lookup efficiency
    //much better than case statements
    prefixInstrMap = {
        {CIL_INS_CEQ, 0},
        {CIL_INS_ARGLIST, 0},
        {CIL_INS_CGT, 0},
        {CIL_INS_CLT, 0},
        {CIL_INS_CLT_UN, 0},
        {CIL_INS_CONSTRAINED, 32},
        {CIL_INS_CPBLK, 0},
        {CIL_INS_ENDFILTER, 0},
        {CIL_INS_INITBLK, 0},
        {CIL_INS_INITOBJ, 32},
        {CIL_INS_LDARG, 16},
        {CIL_INS_LDARGA, 32},
        {CIL_INS_LDFTN, 32},
        {CIL_INS_LDLOC, 16},
        {CIL_INS_LDLOCA, 16},
        {CIL_INS_LDVIRTFTN, 32},
        {CIL_INS_LOCALLOC, 0},
        {CIL_INS_NO, 0},
        {CIL_INS_READONLY, 32},
        {CIL_INS_REFANYTYPE, 0},
        {CIL_INS_RETHROW, 0},
        {CIL_INS_SIZEOF, 32},
        {CIL_INS_STARG, 16},
        {CIL_INS_STLOC, 16},
        {CIL_INS_TAIL, 0},
        {CIL_INS_UNALIGNED, 0},
        {CIL_INS_VOLATILE, 32}
    };
    condInstrMap = {
        {CIL_INS_BEQ, 32},
        {CIL_INS_BEQ_S, 8},
        {CIL_INS_BGE, 32},
        {CIL_INS_BGE_S, 8},
        {CIL_INS_BGE_UN, 32},
        {CIL_INS_BGE_UN_S, 8},
        {CIL_INS_BGT, 32},
        {CIL_INS_BGT_S, 8},
        {CIL_INS_BGT_UN, 32},
        {CIL_INS_BGT_UN_S, 8},
        {CIL_INS_BLE, 32},
        {CIL_INS_BLE_S, 8},
        {CIL_INS_BLE_UN, 32},
        {CIL_INS_BLE_UN_S, 8},
        {CIL_INS_BLT, 32},
        {CIL_INS_BLT_S, 8},
        {CIL_INS_BLT_UN, 32},
        {CIL_INS_BLT_UN_S, 8},
        {CIL_INS_BNE_UN, 32},
        {CIL_INS_BNE_UN_S, 8},
        {CIL_INS_BOX, 32},
        {CIL_INS_BR, 32},
        {CIL_INS_BR_S, 8},
        {CIL_INS_BREAK, 0},
        {CIL_INS_BRFALSE, 32},
        {CIL_INS_BRFALSE_S, 8},
        // case CIL_INS_BRINST:
        //     printf("brinst\n");
        //     break;
        // case CIL_INS_BRINST_S:
        //     printf("brinst.s\n");
        //     break;
        // case CIL_INS_BRNULL:
        //     printf("brnull\n");
        //     break;
        // case CIL_INS_BRNULL_S:
        //     printf("brnull.s\n");
        //     break;
        {CIL_INS_BRTRUE, 32},
        {CIL_INS_BRTRUE_S, 8},
        // case CIL_INS_BRZERO:
        //     printf("brzero\n");
        //     break;
        // case CIL_INS_BRZERO_S:
        //     printf("brzero.s\n");
        //     break;
        {CIL_INS_CALL, 32},
        {CIL_INS_CALLI, 32},
        {CIL_INS_CALLVIRT, 32}
    };

    miscInstrMap = {
        {CIL_INS_ADD, 0},
        {CIL_INS_ADD_OVF, 0},
        {CIL_INS_ADD_OVF_UN, 0},
        {CIL_INS_AND, 0},
        {CIL_INS_CASTCLASS, 32},
        {CIL_INS_CKINITE, 0},
        {CIL_INS_CONV_I, 0},
        {CIL_INS_CONV_I1, 0},
        {CIL_INS_CONV_I2, 0},
        {CIL_INS_CONV_I4, 0},
        {CIL_INS_CONV_I8, 0},
        {CIL_INS_CONV_OVF_i, 0},
        {CIL_INS_CONV_OVF_I_UN, 0},
        {CIL_INS_CONV_OVF_I1, 0},
        {CIL_INS_CONV_OVF_I1_UN, 0},
        {CIL_INS_CONV_OVF_I2, 0},
        {CIL_INS_CONV_OVF_I2_UN, 0},
        {CIL_INS_CONV_OVF_I4, 0},
        {CIL_INS_CONV_OVF_I4_UN, 0},
        {CIL_INS_CONV_OVF_I8, 0},
        {CIL_INS_CONV_OVF_I8_UN, 0},
        {CIL_INS_CONV_OVF_U, 0},
        {CIL_INS_CONV_OVF_U_UN, 0},
        {CIL_INS_CONV_OVF_U1, 0},
        {CIL_INS_CONV_OVF_U1_UN, 0},
        {CIL_INS_CONV_OVF_U2, 0},
        {CIL_INS_CONV_OVF_U2_UN, 0},
        {CIL_INS_CONV_OVF_U4, 0},
        {CIL_INS_CONV_OVF_U4_UN, 0},
        {CIL_INS_CONV_OVF_U8, 0},
        {CIL_INS_CONV_OVF_U8_UN, 0},
        {CIL_INS_CONV_R_UN, 0},
        {CIL_INS_CONV_R4, 0},
        {CIL_INS_CONV_R8, 0},
        {CIL_INS_CONV_U, 0},
        {CIL_INS_CONV_U1, 0},
        {CIL_INS_CONV_U2, 0},
        {CIL_INS_CONV_U4, 0},
        {CIL_INS_CONV_U8, 0},
        {CIL_INS_CPOBJ, 32},
        {CIL_INS_DIV, 0},
        {CIL_INS_DIV_UN, 0},
        {CIL_INS_DUP, 0},
        //CIL_INS_ENDFAULT:
        //printf("endfault
        //break;
        {CIL_INS_ENDFINALLY, 0},
        {CIL_INS_ISINST, 32},
        {CIL_INS_JMP, 32},
        {CIL_INS_LDARG_0, 0},
        {CIL_INS_LDARG_1, 0},
        {CIL_INS_LDARG_2, 0},
        {CIL_INS_LDARG_3, 0},
        {CIL_INS_LDARG_S, 8},
        {CIL_INS_LDARGA_S, 8},
        {CIL_INS_LDC_I4, 32},
        {CIL_INS_LDC_I4_0, 0},
        {CIL_INS_LDC_I4_1, 0},
        {CIL_INS_LDC_I4_2, 0},
        {CIL_INS_LDC_I4_3, 0},
        {CIL_INS_LDC_I4_4, 0},
        {CIL_INS_LDC_I4_5, 0},
        {CIL_INS_LDC_I4_6, 0},
        {CIL_INS_LDC_I4_7, 0},
        {CIL_INS_LDC_I4_8, 0},
        {CIL_INS_LDC_I4_M1, 0},
        {CIL_INS_LDC_I4_S, 8},
        {CIL_INS_LDC_I8, 64},
        {CIL_INS_LDC_R4, 32},
        {CIL_INS_LDC_R8, 64},
        {CIL_INS_LDELM, 32},
        {CIL_INS_LDELM_I, 0},
        {CIL_INS_LDELM_I1, 0},
        {CIL_INS_LDELM_I2, 0},
        {CIL_INS_LDELM_I4, 0},
        {CIL_INS_LDELM_I8, 0},
        {CIL_INS_LDELM_R4, 0},
        {CIL_INS_LDELM_R8, 0},
        {CIL_INS_LDELM_REF, 0},
        {CIL_INS_LDELM_U1, 0},
        {CIL_INS_LDELM_U2, 0},
        {CIL_INS_LDELM_U4, 0},
        //CIL_INS_LDELM_U8:
        //printf("ldelm.u8
        //break;
        {CIL_INS_LDELMA, 32},
        {CIL_INS_LDFLD, 32},
        {CIL_INS_LDFLDA, 32},
        {CIL_INS_LDIND_I, 0},
        {CIL_INS_LDIND_I1, 0},
        {CIL_INS_LDIND_I2, 0},
        {CIL_INS_LDIND_I4, 0},
        {CIL_INS_LDIND_I8, 0},
        {CIL_INS_LDIND_R4, 0},
        {CIL_INS_LDIND_R8, 0},
        {CIL_INS_LDIND_REF, 0},
        {CIL_INS_LDIND_U1, 0},
        {CIL_INS_LDIND_U2, 0},
        {CIL_INS_LDIND_U4, 0},
        //CIL_INS_LDIND_U8:
        //printf("ldind.u8
        //break;
        {CIL_INS_LDLEN, 0},
        {CIL_INS_LDLOC_0, 0},
        {CIL_INS_LDLOC_1, 0},
        {CIL_INS_LDLOC_2, 0},
        {CIL_INS_LDLOC_3, 0},
        {CIL_INS_LDLOC_S, 8},
        {CIL_INS_LDLOCA_S, 8},
        {CIL_INS_LDNULL, 0},
        {CIL_INS_LDOBJ, 32},
        {CIL_INS_LDSFLD, 32},
        {CIL_INS_LDSFLDA, 32},
        {CIL_INS_LDSTR, 32},
        {CIL_INS_LDTOKEN, 32},
        {CIL_INS_LEAVE, 32},
        {CIL_INS_LEAVE_S, 8},
        {CIL_INS_MKREFANY, 32},
        {CIL_INS_MUL, 0},
        {CIL_INS_MUL_OVF, 0},
        {CIL_INS_MUL_OVF_UN, 0},
        {CIL_INS_NEG, 0},
        {CIL_INS_NEWARR, 32},
        {CIL_INS_NEWOBJ, 32},
        {CIL_INS_NOP, 0},
        {CIL_INS_NOT, 0},
        {CIL_INS_OR, 0},
        {CIL_INS_POP, 0},
        {CIL_INS_REFANYVAL, 32},
        {CIL_INS_REM, 0},
        {CIL_INS_REM_UN, 0},
        {CIL_INS_RET, 0},
        {CIL_INS_SHL, 0},
        {CIL_INS_SHR, 0},
        {CIL_INS_SHR_UN, 0},
        {CIL_INS_STARG_S, 8},
        {CIL_INS_STELEM, 32},
        {CIL_INS_STELEM_I, 0},
        {CIL_INS_STELEM_I1, 0},
        {CIL_INS_STELEM_I2, 0},
        {CIL_INS_STELEM_I4, 0},
        {CIL_INS_STELEM_I8, 0},
        {CIL_INS_STELEM_R4, 0},
        {CIL_INS_STELEM_R8, 0},
        {CIL_INS_STELEM_REF, 0},
        {CIL_INS_STFLD, 0},
        {CIL_INS_STIND_I, 0},
        {CIL_INS_STIND_I1, 0},
        {CIL_INS_STIND_I2, 0},
        {CIL_INS_STIND_I4, 0},
        {CIL_INS_STIND_I8, 0},
        {CIL_INS_STIND_R4, 0},
        {CIL_INS_STIND_R8, 0},
        {CIL_INS_STIND_REF, 0},
        {CIL_INS_STLOC_S, 8},
        {CIL_INS_STLOC_0, 0},
        {CIL_INS_STLOC_1, 0},
        {CIL_INS_STLOC_2, 0},
        {CIL_INS_STLOC_3, 0},
        {CIL_INS_STOBJ, 32},
        {CIL_INS_STSFLD, 32},
        {CIL_INS_SUB, 0},
        {CIL_INS_SUB_OVF, 0},
        {CIL_INS_SUB_OVF_UN, 0},
        {CIL_INS_SWITCH, 32},
        {CIL_INS_THROW, 0},
        {CIL_INS_UNBOX, 32},
        {CIL_INS_UNBOX_ANY, 32},
        {CIL_INS_XOR, 0}
    };
}

char * CILDecompiler::hexdump_traits(char *buffer0, const void *data, int size, int operand_size) {
    const unsigned char *pc = (const unsigned char *)data;
    for (int i = 0; i < size; i++){
        if (i >= size - (operand_size/8)){
            sprintf(buffer0, "%s?? ", buffer0);
        } else {
            sprintf(buffer0, "%s%02x ", buffer0, pc[i]);
        }
    }
    return buffer0;
}
char * CILDecompiler::traits_nl(char *traits){
    sprintf(traits, "%s\n", traits);
    return traits;
}

bool CILDecompiler::Setup(int input_type){
    switch(input_type){
        case CIL_DECOMPILER_TYPE_BLCKS:
            type = CIL_DECOMPILER_TYPE_BLCKS;
            break;
        case CIL_DECOMPILER_TYPE_FUNCS:
            type = CIL_DECOMPILER_TYPE_FUNCS;
            break;
        default:
            fprintf(stderr, "[x] unsupported CIL decompiler type\n");
            type = CIL_DECOMPILER_TYPE_UNSET;
            return false;
    }
    return true;
}
int CILDecompiler::update_offset(int operand_size, int i) {
    fprintf(stderr, "[+] updating offset using operand size %d\n", operand_size);
    switch(operand_size){
        case 0:
            break;
        case 8:
            i++;
            break;
        case 16:
            i = i + 2;
            break;
        case 32:
            i = i + 4;
            break;
        case 64:
            i = i + 8;
            break;
        default:
            fprintf(stderr, "[x] unknown operand size %d\n", operand_size);
            i = -1;
    }
    return i;
}

bool CILDecompiler::Decompile(void *data, int data_size, int index){
    const unsigned char *pc = (const unsigned char *)data;
    //char *bytes = NULL;
    vector<Trait*> traits;
    //Let's use a vector for our instructions because C++ has
    //structures for this stuff.
    vector< Instruction* >* instructions = new vector<Instruction *>;
    //We need an iterator for our hashmap searches
    map<int, int>::iterator it;
    uint num_edges = 0;
    for (int i = 0; i < data_size; i++){
        int operand_size = 0;
        bool end_block = false;
        bool end_func = false;
        Instruction *insn = new Instruction;
        //fprintf(stderr, "Instruction being decompiled: 0x%x\n", pc[i]);
        //TODO: need to add all raw bytes, not just masked bytes, to instruction set collected
        if (insn->instruction == CIL_INS_PREFIX){
            //Let's add prefix instruction to our instructions
            insn->instruction = pc[i];
            insn->operand_size = it->second;
            insn->offset = i;
            instructions->push_back(insn);
            //Then let's move on to the next instruction
            i++;
            //fprintf(stderr, "Instruction being decompiled: 0x%x\n", pc[i]);
            //Then let's create a new instruction for the ... new instruction
            insn = new Instruction;
            insn->instruction = pc[i];
            it = prefixInstrMap.find(pc[i]);
            if(it != prefixInstrMap.end()) {
                fprintf(stderr, "[+] found prefix opcode 0x%02x at offset %d with operand size: %d\n", pc[i], i, it->second);
                insn->instruction = pc[i];
                insn->operand_size = it->second;
                insn->offset = i;
                instructions->push_back(insn);
            } else {
                fprintf(stderr, "[x] unknown prefix opcode 0x%02x at offset %d\n", pc[i], i);
                return false;
            }
        } else {
            it = condInstrMap.find(pc[i]);
            if(it != condInstrMap.end()) {
                    num_edges++;
                    insn->instruction = pc[i];
                    insn->operand_size = it->second;
                    insn->offset = i;
                    instructions->push_back(insn);   
                    end_block = true;
                    fprintf(stderr, "[+] end block found -> opcode 0x%02x at offset %d\n", pc[i], i);
            } else {
                it = miscInstrMap.find(pc[i]);
                if(it != miscInstrMap.end()) {
                    fprintf(stderr, "[+] found misc opcode 0x%02x at offset %d with operand size: %d\n", pc[i], i, it->second);
                    insn->instruction = pc[i];
                    insn->operand_size = it->second;
                    insn->offset = i;
                    instructions->push_back(insn);
                } else {
                    fprintf(stderr, "[x] unknown opcode 0x%02x at offset %d\n", pc[i], i);
                    return false;
                }
            }
        }
        if(insn->instruction == CIL_INS_RET) {
            end_func = true;
        }
        
        int updated = update_offset(insn->operand_size, i);
        if (updated != -1) {
            i = updated;
        }
        //If we're at the end of a block, at the end of a function, or
        //at the end of our data then we need to store the trait data.
        if ((end_func || end_block && i < data_size - 1) ||
            ((end_func == false && end_block == false) && i == data_size -1)) {
            Trait *ctrait = new Trait;
            ctrait->instructions = instructions;
            ctrait->corpus = sections[index].corpus;
            //Limiting to x86 for now but this should be set by the PE parsing code
            //higher up in the call-stack.
            ctrait->architecture = CS_ARCH_X86;
            //The first offset of the first instruction will give us the offset
            //of our trait.
            ctrait->offset = instructions->front()->offset;
            ctrait->trait = ConvTraitBytes(*instructions);
            ctrait->bytes = ConvBytes(*instructions, data, data_size);
            //Since traits are differentiated by blocks then this will always be 1
            //maybe this should differentiated from in the future?
            ctrait->blocks = 1;
            ctrait->edges = num_edges;
            ctrait->size = SizeOfTrait(*instructions);
            ctrait->invalid_instructions = 0; //TODO
            ctrait->type = "block"; //TODO support both types
            ctrait->corpus = string(sections[index].corpus);
            //The cyclomatic complexity differs by type of trait. 
            //Which for now only supports block.
            ctrait->cyclomatic_complexity = num_edges - 1 + 2;
            ctrait->average_instructions_per_block = 0; //TODO for function traits
            ctrait->bytes_entropy = Entropy(ctrait->bytes);
            ctrait->trait_entropy = Entropy(ctrait->trait);
            //ctrait->trait_sha256 = SHA256(ctrait->bytes.c_str()); TODO
            //ctrait->bytes_sha256 = SHA256(ctrait->bytes.c_str()); TODO
            traits.push_back(ctrait);
            //The number of edges needs to be reset once the trait is stored.
            num_edges = 0;
       }
    }
    return true;
}

string CILDecompiler::ConvTraitBytes(vector< Instruction* > allinst) {
    string rstr;
    for(auto inst : allinst) {
        char hexbytes[5];
        sprintf(hexbytes, "%02x ", inst->instruction);
        hexbytes[4] = '\0';
        rstr.append(string(hexbytes));
        cout << hexbytes;
        for(int i = 0; i < inst->operand_size/8; i++) {
            cout << "?? ";
            rstr.append("?? ");
        }
    }
    cout << "\n";
    return rstr;
}

uint CILDecompiler::SizeOfTrait(vector< Instruction* > allinst) {
    int begin_offset = allinst.front()->offset;
    int end_offset = allinst.back()->offset;
    uint size = (end_offset-begin_offset)+(allinst.back()->operand_size/8)+1;
    return size;
}

string CILDecompiler::ConvBytes(vector< Instruction* > allinst, void *data, int data_size) {
    string byte_rep;
    int begin_offset = allinst.front()->offset;
    int end_offset = allinst.back()->offset;
    char *cdata = (char *)data;
    //We need to incorporate the operand size into the data collected starting at
    //the last offset.
    for(int i = 0; i < SizeOfTrait(allinst); i++) {
        char hexbytes[5];
        sprintf(hexbytes, "%02x ", cdata[i]);
        hexbytes[4] = '\0';
        byte_rep.append(string(hexbytes));
        cout << hexbytes;
    }
    cout << "\n";
    return byte_rep;
}

void CILDecompiler::SetThreads(uint threads, uint thread_cycles, uint thread_sleep, uint index){
    sections[index].threads = threads;
    sections[index].thread_cycles = thread_cycles;
    sections[index].thread_sleep = thread_sleep;
}

void CILDecompiler::SetCorpus(char *corpus, uint index){
    sections[index].corpus = corpus;
}

void CILDecompiler::SetInstructions(bool instructions, uint index){
    sections[index].instructions = instructions;
}

/*
string CILDecompiler::GetTrait(struct Trait *trait, bool pretty){
    json data;
    data["type"] = trait->type;
    data["corpus"] = trait->corpus;
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
*/

void CILDecompiler::WriteTraits(char *file_path){
    FILE *fd = fopen(file_path, "w");
    for (int i = 0; i < CIL_DECOMPILER_MAX_SECTIONS; i++){
        if (sections[i].function_traits != NULL){
            fwrite(sections[i].function_traits, sizeof(char), strlen(sections[i].function_traits), fd);
        }
        if (sections[i].block_traits != NULL){
            fwrite(sections[i].block_traits, sizeof(char), strlen(sections[i].block_traits), fd);
        }
    }
    fclose(fd);
}
void CILDecompiler::PrintTraits(){
    for (int i = 0; i < CIL_DECOMPILER_MAX_SECTIONS; i++){
        if (sections[i].function_traits != NULL){
            printf("%s", sections[i].function_traits);
        }
        if (sections[i].block_traits != NULL){
            printf("%s", sections[i].block_traits);
        }
    }
}

/*
void * CILDecompiler::DecompileWorker(void *args) {

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
*/
/*
void * CILDecompiler::TraitWorker(void *args){
    struct Trait *trait = (struct Trait *)args;
    if (trait->blocks == 0 &&
        (strcmp(trait->type, "function") == 0 ||
        strcmp(trait->type, "block") == 0)){
        trait->blocks++;
    }
    trait->bytes_entropy = Entropy(string(trait->bytes));
    trait->trait_entropy = Entropy(string(trait->trait));
    string bytes_sha256 = SHA256(trait->bytes);
    trait->bytes_sha256 = (char *)malloc(bytes_sha256.length()+1);
    memset(trait->bytes_sha256, 0, bytes_sha256.length()+1);
    memcpy(trait->bytes_sha256, bytes_sha256.c_str(), bytes_sha256.length());
    string trait_sha256 = SHA256(trait->trait);
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
*/
bool CILDecompiler::IsVisited(map<uint64_t, int> &visited, uint64_t address) {
    return visited.find(address) != visited.end();
}

void CILDecompiler::ClearTrait(struct Trait *trait){
    trait->tmp_bytes.clear();
    trait->edges = 0;
    trait->instructions = 0;
    trait->blocks = 0;
    trait->offset = 0;
    trait->size = 0;
    trait->invalid_instructions = 0;
    trait->bytes_sha256 = NULL;
}

/*
void CILDecompiler::FreeTraits(uint index){
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
*/

CILDecompiler::~CILDecompiler(){
    for (int i = 0; i < CIL_DECOMPILER_MAX_SECTIONS; i++){
        if (sections[i].function_traits != NULL){
            free(sections[i].function_traits);
        }
        if (sections[i].block_traits != NULL){
            free(sections[i].block_traits);
        }
    }
}