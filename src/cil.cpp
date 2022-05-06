#include "cil.h"

using namespace binlex;
using json = nlohmann::json;
#ifndef _WIN32
static pthread_mutex_t DECOMPILER_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#else
CRITICAL_SECTION csDecompiler;
#endif

CILDecompiler::CILDecompiler(const binlex::File &firef) : DecompilerBase(firef) {
    int type = CIL_DECOMPILER_TYPE_UNSET;
    for (int i = 0; i < CIL_DECOMPILER_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].ntraits = 0;
        sections[i].data = NULL;
        sections[i].data_size = 0;
        sections[i].threads = 1;
        sections[i].thread_cycles = 1;
        sections[i].thread_sleep = 500;
        sections[i].corpus = g_args.options.corpus;
        sections[i].instructions = false;
        sections[i].arch_str = NULL;
    }
    //Maps give us O(nlogn) lookup efficiency
    //much better than case statements
    prefixInstrMap = {
        {CIL_INS_CEQ, 0},
        {CIL_INS_ARGLIST, 0},
        {CIL_INS_CGT, 0},
        {CIL_INS_CGT_UN, 0},
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
        {CIL_INS_BRTRUE_S, 8}
        // case CIL_INS_BRZERO:
        //     printf("brzero\n");
        //     break;
        // case CIL_INS_BRZERO_S:
        //     printf("brzero.s\n");
        //     break;
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
        {CIL_INS_STFLD, 32},
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
        {CIL_INS_XOR, 0},
        {CIL_INS_CALL, 32},
        {CIL_INS_CALLI, 32},
        {CIL_INS_CALLVIRT, 32}
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
        case CIL_DECOMPILER_TYPE_ALL:
            type = CIL_DECOMPILER_TYPE_ALL;
            break;
        default:
            fprintf(stderr, "[x] unsupported CIL decompiler type\n");
            type = CIL_DECOMPILER_TYPE_UNSET;
            return false;
    }
    return true;
}
int CILDecompiler::update_offset(int operand_size, int i) {
    //fprintf(stderr, "[+] updating offset using operand size %d\n", operand_size);
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
    vector<Trait*> traits;
    vector<Trait*> ftraits;
    vector< Instruction* >* instructions = new vector<Instruction *>;
    vector< Instruction* >* finstructions = new vector<Instruction *>;
    //We need an iterator for our hashmap searches
    map<int, int>::iterator it;
    uint num_edges = 0;
    uint num_f_edges = 0;
    uint num_instructions = 0;
    uint num_f_instructions = 0;
    uint func_block_count = 0;
    for (int i = 0; i < data_size; i++){
        int operand_size = 0;
        bool end_block = false;
        bool end_func = false;
        Instruction *insn = new Instruction;
        PRINT_DEBUG("Instruction being decompiled: 0x%x\n", pc[i]);
        if (pc[i] == CIL_INS_PREFIX){
            //Let's add prefix instruction to our instructions
            insn->instruction = pc[i];
            insn->operand_size = 0;
            insn->offset = i;
            instructions->push_back(insn);
            finstructions->push_back(insn);
            //Then let's move on to the next instruction
            i++;
            PRINT_DEBUG("Instruction being decompiled: 0x%x\n", pc[i]);
            //Then let's create a new instruction for the ... new instruction
            insn = new Instruction;
            insn->instruction = pc[i];
            it = prefixInstrMap.find(pc[i]);
            if(it != prefixInstrMap.end()) {
                PRINT_DEBUG("[+] found prefix opcode 0x%02x at offset %d with operand size: %d\n", pc[i], i, it->second);
                insn->instruction = pc[i];
                insn->operand_size = it->second;
                insn->offset = i;
                instructions->push_back(insn);
                finstructions->push_back(insn);
                num_instructions++;
                num_f_instructions++;
            } else {
                PRINT_ERROR_AND_EXIT( "[x] unknown prefix opcode 0x%02x at offset %d\n", pc[i], i);
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
                    finstructions->push_back(insn);
                    end_block = true;
                    num_instructions++;
                    num_f_instructions++;
                    PRINT_DEBUG("[+] end block found -> opcode 0x%02x at offset %d\n", pc[i], i);
            } else {
                it = miscInstrMap.find(pc[i]);
                if(it != miscInstrMap.end()) {
                    PRINT_DEBUG("[+] found misc opcode 0x%02x at offset %d with operand size: %d\n", pc[i], i, it->second);
                    insn->instruction = pc[i];
                    insn->operand_size = it->second;
                    insn->offset = i;
                    instructions->push_back(insn);
                    finstructions->push_back(insn);
                    num_instructions++;
                    num_f_instructions++;
                } else {
                    PRINT_ERROR_AND_EXIT("[x] unknown opcode 0x%02x at offset %d\n", pc[i], i);
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
        //at the end of our data then we need to store the block trait data.
        //Even the end of a function should be considered a "block".
        if ((end_func || end_block && i < data_size - 1) ||
            ((end_block == false && end_func == false) && i == data_size -1)) {
            Trait *ctrait = new Trait;
            ctrait->instructions = instructions;
            ctrait->corpus = sections[index].corpus;
            //Limiting to x86 for now but this should be set by the PE parsing code
            //higher up in the call-stack.
            ctrait->architecture = "x86";
            //The first offset of the first instruction will give us the offset
            //of our trait.
            uint trait_offset = instructions->front()->offset;
            PRINT_DEBUG("Adding offset to trait: %d\n", trait_offset);
            ctrait->offset = instructions->front()->offset;
            ctrait->num_instructions = num_instructions;
            ctrait->trait = ConvTraitBytes(*instructions);
            ctrait->bytes = ConvBytes(*instructions, data, data_size);
            //Since traits are differentiated by blocks then this will always be 1
            //maybe this should be different in the future?
            ctrait->blocks = 1;
            ctrait->edges = num_edges;
            ctrait->size = SizeOfTrait(*instructions);
            ctrait->invalid_instructions = 0; //TODO
            ctrait->type = "block";
            ctrait->corpus = string(sections[index].corpus);
            //The cyclomatic complexity differs by type of trait.
            //Which for now only supports block.
            ctrait->cyclomatic_complexity = num_edges - 1 + 2;
            ctrait->average_instructions_per_block = instructions->size();
            ctrait->bytes_entropy = Entropy(ctrait->bytes);
            ctrait->trait_entropy = Entropy(ctrait->trait);
            ctrait->trait_sha256 = SHA256(&ctrait->trait[0]);
            ctrait->bytes_sha256 = SHA256(&ctrait->bytes[0]);
            //The number of edges needs to be reset once the trait is stored.
            num_edges = 0;
            sections[index].block_traits.push_back(ctrait);
            //Once we're done adding a trait we need to create a new set of instructions
            //for the next trait.
            instructions = new vector<Instruction *>;
            num_instructions = 0;
            func_block_count++;
       }
       if ((end_func && i < data_size - 1) ||
            ((end_func == false) && i == data_size -1)) {
            Trait *ftrait = new Trait;
            ftrait->instructions = finstructions;
            ftrait->corpus = sections[index].corpus;
            //Limiting to x86 for now but this should be set by the PE parsing code
            //higher up in the call-stack.
            ftrait->architecture = "x86";
            //The first offset of the first instruction will give us the offset
            //of our trait.
            uint trait_offset = finstructions->front()->offset;
            PRINT_DEBUG("Adding offset to function trait: %d\n", trait_offset);
            ftrait->offset = finstructions->front()->offset;
            ftrait->num_instructions = num_f_instructions;
            ftrait->trait = ConvTraitBytes(*finstructions);
            ftrait->bytes = ConvBytes(*finstructions, data, data_size);
            ftrait->blocks = func_block_count;
            ftrait->edges = num_edges;
            ftrait->size = SizeOfTrait(*finstructions);
            ftrait->invalid_instructions = 0; //TODO
            ftrait->type = "function";
            ftrait->corpus = string(sections[index].corpus);
            ftrait->cyclomatic_complexity = num_f_edges - func_block_count + 2;
            ftrait->average_instructions_per_block = finstructions->size()/func_block_count;
            ftrait->bytes_entropy = Entropy(ftrait->bytes);
            ftrait->trait_entropy = Entropy(ftrait->trait);
            ftrait->trait_sha256 = SHA256(&ftrait->trait[0]);
            ftrait->bytes_sha256 = SHA256(&ftrait->bytes[0]);
            //The number of edges needs to be reset once the trait is stored.
            num_edges = 0;
            sections[index].function_traits.push_back(ftrait);
            //Once we're done adding a trait we need to create a new set of instructions
            //for the next trait.
            finstructions = new vector<Instruction *>;
            num_f_instructions = 0;
            func_block_count = 0;
       }
    }
    return true;
}

string CILDecompiler::ConvTraitBytes(vector< Instruction* > allinst) {
    string rstr = "";
    string fstr = "";
    for(auto inst : allinst) {
        if(inst->instruction == CIL_INS_NOP) {
            rstr.append("??");
            rstr.append(" ");
        } else {
            char hexbytes[3];
            sprintf(hexbytes, "%02x", inst->instruction);
            hexbytes[2] = '\0';
            rstr.append(string(hexbytes));
            rstr.append(" ");
        }
        for(int i = 0; i < inst->operand_size/8; i++) {
            rstr.append("??");
            rstr.append(" ");
        }
    }
    fstr = TrimRight(rstr);
    return fstr;
}

uint CILDecompiler::SizeOfTrait(vector< Instruction* > inst) {
    int begin_offset = inst.front()->offset;
    int end_offset = inst.back()->offset;
    uint size = (end_offset-begin_offset)+(inst.back()->operand_size/8)+1;
    return size;
}

string CILDecompiler::ConvBytes(vector< Instruction* > allinst, void *data, int data_size) {
    string byte_rep = "";
    string byte_rep_t;
    int begin_offset = allinst.front()->offset;
    if(begin_offset > data_size) {
        PRINT_ERROR_AND_EXIT("Beginning offset trait offset:\
         %d cannot be greater than total data length: %d", begin_offset, data_size);
    }
    uint trait_size = SizeOfTrait(allinst);
    unsigned char *cdata = (unsigned char *)data;
    char hexbytes[3];
    for(int i = begin_offset; i < begin_offset+trait_size; i++) {
        sprintf(hexbytes, "%02x", cdata[i]);
        hexbytes[2] = '\0';
        byte_rep.append(string(hexbytes));
        byte_rep.append(" ");
    }
    byte_rep_t = TrimRight(byte_rep);
    return byte_rep_t;
}

json CILDecompiler::GetTrait(struct Trait *trait){
    json data;
    data["type"] = trait->type;
    data["corpus"] = trait->corpus;
    data["tags"] = g_args.options.tags;
    data["mode"] = g_args.options.mode;
    data["bytes"] = trait->bytes;
    data["trait"] = trait->trait;
    data["edges"] = trait->edges;
    data["blocks"] = trait->blocks;
    data["instructions"] = trait->num_instructions;
    data["size"] = trait->size;
    data["offset"] = trait->offset;
    data["bytes_entropy"] = trait->bytes_entropy;
    data["bytes_sha256"] = trait->bytes_sha256;
    data["trait_sha256"] = trait->trait_sha256;
    data["trait_entropy"] = trait->trait_entropy;
    data["invalid_instructions"] = trait->invalid_instructions;
    data["cyclomatic_complexity"] = trait->cyclomatic_complexity;
    data["average_instructions_per_block"] = trait->average_instructions_per_block;
    return data;
}

vector<json> CILDecompiler::GetTraits(){
    vector<json> traitsjson;
    for (int i = 0; i < CIL_DECOMPILER_MAX_SECTIONS; i++){
        if ((sections[i].function_traits.size() > 0) && (type == CIL_DECOMPILER_TYPE_ALL
        || type == CIL_DECOMPILER_TYPE_FUNCS)){
            for(auto trait : sections[i].function_traits) {
                json jdata(GetTrait(trait));
                traitsjson.push_back(jdata);
            }
        }
        if ((sections[i].block_traits.size() > 0) && (type == CIL_DECOMPILER_TYPE_ALL
        || type == CIL_DECOMPILER_TYPE_BLCKS)){
            for(auto trait : sections[i].block_traits) {
                json jdata(GetTrait(trait));
                traitsjson.push_back(jdata);
            }
        }
    }
    return traitsjson;
}

CILDecompiler::~CILDecompiler() {
    for (int i = 0; i < CIL_DECOMPILER_MAX_SECTIONS; i++){
        if (sections[i].function_traits.size() > 0) {
            for(auto trait : sections[i].function_traits) {
                delete trait->instructions;
            }
        }
        if (sections[i].block_traits.size() > 0) {
            for(auto trait : sections[i].block_traits) {
                delete trait->instructions;
            }
        }
    }
}
