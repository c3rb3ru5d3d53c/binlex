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

using namespace std;
using namespace binlex;

CILDecompiler::CILDecompiler(){
    int type = CIL_DECOMPILER_TYPE_UNSET;
    for (int i = 0; i < CIL_DECOMPILER_MAX_SECTIONS; i++){
        sections[i].function_traits = NULL;
        sections[i].block_traits = NULL;
    }
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
bool CILDecompiler::Decompile(void *data, int data_size, int index){
    const unsigned char *pc = (const unsigned char *)data;
    char *bytes = NULL;
    char *traits = (char *)malloc(data_size * 2 + data_size + 1);
    memset((void *)traits, 0, data_size * 2 + data_size);
    for (int i = 0; i < data_size; i++){
        int operand_size = 0;
        bool end_block = false;
        bool end_func = false;
        if (pc[i] == CIL_INS_PREFIX){
            i++;
            switch(pc[i]){
                case CIL_INS_CEQ:
                    break;
                case CIL_INS_ARGLIST:
                    break;
                case CIL_INS_CGT:
                    break;
                case CIL_INS_CLT:
                    break;
                case CIL_INS_CLT_UN:
                    break;
                case CIL_INS_CONSTRAINED:
                    operand_size = 32;
                    break;
                case CIL_INS_CPBLK:
                    break;
                case CIL_INS_ENDFILTER:
                    break;
                case CIL_INS_INITBLK:
                    break;
                case CIL_INS_INITOBJ:
                    operand_size = 32;
                    break;
                case CIL_INS_LDARG:
                    operand_size = 16;
                    break;
                case CIL_INS_LDARGA:
                    operand_size = 16;
                    break;
                case CIL_INS_LDFTN:
                    operand_size = 32;
                    break;
                case CIL_INS_LDLOC:
                    operand_size = 16;
                    break;
                case CIL_INS_LDLOCA:
                    operand_size = 16;
                    break;
                case CIL_INS_LDVIRTFTN:
                    operand_size = 32;
                    break;
                case CIL_INS_LOCALLOC:
                    break;
                case CIL_INS_NO:
                    break;
                case CIL_INS_READONLY:
                    operand_size = 32;
                    break;
                case CIL_INS_REFANYTYPE:
                    break;
                case CIL_INS_RETHROW:
                    break;
                case CIL_INS_SIZEOF:
                    operand_size = 32;
                    break;
                case CIL_INS_STARG:
                    operand_size = 16;
                    break;
                case CIL_INS_STLOC:
                    operand_size = 16;
                    break;
                case CIL_INS_TAIL:
                    break;
                case CIL_INS_UNALIGNED:
                    break;
                case CIL_INS_VOLATILE:
                    operand_size = 32;
                    break;
                default:
                    fprintf(stderr, "[x] unknown prefix opcode 0x%02x at offset %d\n", pc[i], i);
                    free(traits);
                    return false;
            }
            if (operand_size <= 0){
                CILDecompiler::hexdump_traits(traits, &pc[i-1], 2, 0);
            } else {
                CILDecompiler::hexdump_traits(traits, &pc[i-1], (operand_size/8)+2, operand_size);
            }
        } else {
            switch(pc[i]){
                case CIL_INS_ADD:
                    break;
                case CIL_INS_ADD_OVF:
                    break;
                case CIL_INS_ADD_OVF_UN:
                    break;
                case CIL_INS_AND:
                    break;
                case CIL_INS_BEQ:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BEQ_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BGE:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BGE_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BGE_UN:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BGE_UN_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BGT:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BGT_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BGT_UN:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BGT_UN_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BLE:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BLE_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BLE_UN:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BLE_UN_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BLT:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BLT_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BLT_UN:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BLT_UN_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BNE_UN:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BNE_UN_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BOX:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BR:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BR_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                case CIL_INS_BREAK:
                    break;
                case CIL_INS_BRFALSE:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BRFALSE_S:
                    end_block = true;
                    operand_size = 8;
                    break;
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
                case CIL_INS_BRTRUE:
                    end_block = true;
                    operand_size = 32;
                    break;
                case CIL_INS_BRTRUE_S:
                    end_block = true;
                    operand_size = 8;
                    break;
                // case CIL_INS_BRZERO:
                //     printf("brzero\n");
                //     break;
                // case CIL_INS_BRZERO_S:
                //     printf("brzero.s\n");
                //     break;
                case CIL_INS_CALL:
                    operand_size = 32;
                    break;
                case CIL_INS_CALLI:
                    operand_size = 32;
                    break;
                case CIL_INS_CALLVIRT:
                    operand_size = 32;
                    break;
                case CIL_INS_CASTCLASS:
                    operand_size = 32;
                    break;
                case CIL_INS_CKINITE:
                    break;
                case CIL_INS_CONV_I:
                    break;
                case CIL_INS_CONV_I1:
                    break;
                case CIL_INS_CONV_I2:
                    break;
                case CIL_INS_CONV_I4:
                    break;
                case CIL_INS_CONV_I8:
                    break;
                case CIL_INS_CONV_OVF_i:
                    break;
                case CIL_INS_CONV_OVF_I_UN:
                    break;
                case CIL_INS_CONV_OVF_I1:
                    break;
                case CIL_INS_CONV_OVF_I1_UN:
                    break;
                case CIL_INS_CONV_OVF_I2:
                    break;
                case CIL_INS_CONV_OVF_I2_UN:
                    break;
                case CIL_INS_CONV_OVF_I4:
                    break;
                case CIL_INS_CONV_OVF_I4_UN:
                    break;
                case CIL_INS_CONV_OVF_I8:
                    break;
                case CIL_INS_CONV_OVF_I8_UN:
                    break;
                case CIL_INS_CONV_OVF_U:
                    break;
                case CIL_INS_CONV_OVF_U_UN:
                    break;
                case CIL_INS_CONV_OVF_U1:
                    break;
                case CIL_INS_CONV_OVF_U1_UN:
                    break;
                case CIL_INS_CONV_OVF_U2:
                    break;
                case CIL_INS_CONV_OVF_U2_UN:
                    break;
                case CIL_INS_CONV_OVF_U4:
                    break;
                case CIL_INS_CONV_OVF_U4_UN:
                    break;
                case CIL_INS_CONV_OVF_U8:
                    break;
                case CIL_INS_CONV_OVF_U8_UN:
                    break;
                case CIL_INS_CONV_R_UN:
                    break;
                case CIL_INS_CONV_R4:
                    break;
                case CIL_INS_CONV_R8:
                    break;
                case CIL_INS_CONV_U:
                    break;
                case CIL_INS_CONV_U1:
                    break;
                case CIL_INS_CONV_U2:
                    break;
                case CIL_INS_CONV_U4:
                    break;
                case CIL_INS_CONV_U8:
                    break;
                case CIL_INS_CPOBJ:
                    operand_size = 32;
                    break;
                case CIL_INS_DIV:
                    break;
                case CIL_INS_DIV_UN:
                    break;
                case CIL_INS_DUP:
                    break;
                // case CIL_INS_ENDFAULT:
                //     printf("endfault\n");
                //     break;
                case CIL_INS_ENDFINALLY:
                    break;
                case CIL_INS_ISINST:
                    operand_size = 32;
                    break;
                case CIL_INS_JMP:
                    operand_size = 32;
                    break;
                case CIL_INS_LDARG_0:
                    break;
                case CIL_INS_LDARG_1:
                    break;
                case CIL_INS_LDARG_2:
                    break;
                case CIL_INS_LDARG_3:
                    break;
                case CIL_INS_LDARG_S:
                    operand_size = 8;
                    break;
                case CIL_INS_LDARGA_S:
                    operand_size = 8;
                    break;
                case CIL_INS_LDC_I4:
                    operand_size = 32;
                    break;
                case CIL_INS_LDC_I4_0:
                    break;
                case CIL_INS_LDC_I4_1:
                    break;
                case CIL_INS_LDC_I4_2:
                    break;
                case CIL_INS_LDC_I4_3:
                    break;
                case CIL_INS_LDC_I4_4:
                    break;
                case CIL_INS_LDC_I4_5:
                    break;
                case CIL_INS_LDC_I4_6:
                    break;
                case CIL_INS_LDC_I4_7:
                    break;
                case CIL_INS_LDC_I4_8:
                    break;
                case CIL_INS_LDC_I4_M1:
                    break;
                case CIL_INS_LDC_I4_S:
                    operand_size = 8;
                    break;
                case CIL_INS_LDC_I8:
                    operand_size = 64;
                    break;
                case CIL_INS_LDC_R4:
                    operand_size = 32;
                    break;
                case CIL_INS_LDC_R8:
                    operand_size = 64;
                    break;
                case CIL_INS_LDELM:
                    operand_size = 32;
                    break;
                case CIL_INS_LDELM_I:
                    break;
                case CIL_INS_LDELM_I1:
                    break;
                case CIL_INS_LDELM_I2:
                    break;
                case CIL_INS_LDELM_I4:
                    break;
                case CIL_INS_LDELM_I8:
                    break;
                case CIL_INS_LDELM_R4:
                    break;
                case CIL_INS_LDELM_R8:
                    break;
                case CIL_INS_LDELM_REF:
                    break;
                case CIL_INS_LDELM_U1:
                    break;
                case CIL_INS_LDELM_U2:
                    break;
                case CIL_INS_LDELM_U4:
                    break;
                // case CIL_INS_LDELM_U8:
                //     printf("ldelm.u8\n");
                //     break;
                case CIL_INS_LDELMA:
                    operand_size = 32;
                    break;
                case CIL_INS_LDFLD:
                    operand_size = 32;
                    break;
                case CIL_INS_LDFLDA:
                    operand_size = 32;
                    break;
                case CIL_INS_LDIND_I:
                    break;
                case CIL_INS_LDIND_I1:
                    break;
                case CIL_INS_LDIND_I2:
                    break;
                case CIL_INS_LDIND_I4:
                    break;
                case CIL_INS_LDIND_I8:
                    break;
                case CIL_INS_LDIND_R4:
                    break;
                case CIL_INS_LDIND_R8:
                    break;
                case CIL_INS_LDIND_REF:
                    break;
                case CIL_INS_LDIND_U1:
                    break;
                case CIL_INS_LDIND_U2:
                    break;
                case CIL_INS_LDIND_U4:
                    break;
                // case CIL_INS_LDIND_U8:
                //     printf("ldind.u8\n");
                //     break;
                case CIL_INS_LDLEN:
                    break;
                case CIL_INS_LDLOC_0:
                    break;
                case CIL_INS_LDLOC_1:
                    break;
                case CIL_INS_LDLOC_2:
                    break;
                case CIL_INS_LDLOC_3:
                    break;
                case CIL_INS_LDLOC_S:
                    operand_size = 8;
                    break;
                case CIL_INS_LDLOCA_S:
                    operand_size = 8;
                    break;
                case CIL_INS_LDNULL:
                    break;
                case CIL_INS_LDOBJ:
                    operand_size = 32;
                    break;
                case CIL_INS_LDSFLD:
                    operand_size = 32;
                    break;
                case CIL_INS_LDSFLDA:
                    operand_size = 32;
                    break;
                case CIL_INS_LDSTR:
                    operand_size = 32;
                    break;
                case CIL_INS_LDTOKEN:
                    operand_size = 32;
                    break;
                case CIL_INS_LEAVE:
                    operand_size = 32;
                    break;
                case CIL_INS_LEAVE_S:
                    operand_size = 8;
                    break;
                case CIL_INS_MKREFANY:
                    operand_size = 32;
                    break;
                case CIL_INS_MUL:
                    break;
                case CIL_INS_MUL_OVF:
                    break;
                case CIL_INS_MUL_OVF_UN:
                    break;
                case CIL_INS_NEG:
                    break;
                case CIL_INS_NEWARR:
                    operand_size = 32;
                    break;
                case CIL_INS_NEWOBJ:
                    operand_size = 32;
                    break;
                case CIL_INS_NOP:
                    break;
                case CIL_INS_NOT:
                    break;
                case CIL_INS_OR:
                    break;
                case CIL_INS_POP:
                    break;
                case CIL_INS_REFANYVAL:
                    operand_size = 32;
                    break;
                case CIL_INS_REM:
                    break;
                case CIL_INS_REM_UN:
                    break;
                case CIL_INS_RET:
                    end_func = true;
                    break;
                case CIL_INS_SHL:
                    break;
                case CIL_INS_SHR:
                    break;
                case CIL_INS_SHR_UN:
                    break;
                case CIL_INS_STARG_S:
                    operand_size = 8;
                    break;
                case CIL_INS_STELEM:
                    operand_size = 32;
                    break;
                case CIL_INS_STELEM_I:
                    break;
                case CIL_INS_STELEM_I1:
                    break;
                case CIL_INS_STELEM_I2:
                    break;
                case CIL_INS_STELEM_I4:
                    break;
                case CIL_INS_STELEM_I8:
                    break;
                case CIL_INS_STELEM_R4:
                    break;
                case CIL_INS_STELEM_R8:
                    break;
                case CIL_INS_STELEM_REF:
                    break;
                case CIL_INS_STFLD:
                    break;
                case CIL_INS_STIND_I:
                    break;
                case CIL_INS_STIND_I1:
                    break;
                case CIL_INS_STIND_I2:
                    break;
                case CIL_INS_STIND_I4:
                    break;
                case CIL_INS_STIND_I8:
                    break;
                case CIL_INS_STIND_R4:
                    break;
                case CIL_INS_STIND_R8:
                    break;
                case CIL_INS_STIND_REF:
                    break;
                case CIL_INS_STLOC_S:
                    operand_size = 8;
                    break;
                case CIL_INS_STLOC_0:
                    break;
                case CIL_INS_STLOC_1:
                    break;
                case CIL_INS_STLOC_2:
                    break;
                case CIL_INS_STLOC_3:
                    break;
                case CIL_INS_STOBJ:
                    operand_size = 32;
                    break;
                case CIL_INS_STSFLD:
                    operand_size = 32;
                    break;
                case CIL_INS_SUB:
                    break;
                case CIL_INS_SUB_OVF:
                    break;
                case CIL_INS_SUB_OVF_UN:
                    break;
                case CIL_INS_SWITCH:
                    operand_size = 32;
                    break;
                case CIL_INS_THROW:
                    break;
                case CIL_INS_UNBOX:
                    operand_size = 32;
                    break;
                case CIL_INS_UNBOX_ANY:
                    operand_size = 32;
                    break;
                case CIL_INS_XOR:
                    break;
                default:
                    fprintf(stderr, "[x] unknown opcode 0x%02x at offset %d\n", pc[i], i);
                    free(traits);
                    return false;
            }
            if (operand_size <= 0){
                CILDecompiler::hexdump_traits(traits, &pc[i], 1, 0);
            } else {
                CILDecompiler::hexdump_traits(traits, &pc[i], (operand_size/8)+1, operand_size);
            }
        }
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
                free(traits);
                return false;
        }
        if (end_block == true &&
            type == CIL_DECOMPILER_TYPE_BLCKS &&
            i < data_size - 1){
            traits_nl(traits);
        }
        if (end_func == true &&
            type == CIL_DECOMPILER_TYPE_FUNCS &&
            i < data_size - 1){
            traits_nl(traits);
        }
        if ((end_block == false || end_func == false) && i == data_size -1){
            traits_nl(traits);
        }
    }
    if (type == CIL_DECOMPILER_TYPE_BLCKS){
        sections[index].block_traits = (char *)malloc(strlen(traits)+1);
        memset(sections[index].block_traits, 0, strlen(traits)+1);
        memcpy(sections[index].block_traits, traits, strlen(traits));
    }
    if (type == CIL_DECOMPILER_TYPE_FUNCS){
        sections[index].function_traits = (char *)malloc(strlen(traits)+1);
        memset(sections[index].function_traits, 0, strlen(traits)+1);
        memcpy(sections[index].function_traits, traits, strlen(traits));
    }
    free(traits);
    return true;
}
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