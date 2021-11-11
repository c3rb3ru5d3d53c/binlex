#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <assert.h>
#include <byteswap.h>
#include <capstone/capstone.h>
#include "common.h"

#ifndef CIL_H
#define CIL_H

// CIL Decompiler Types
#define CIL_DECOMPILER_TYPE_FUNCS 0
#define CIL_DECOMPILER_TYPE_BLCKS 1
#define CIL_DECOMPILER_TYPE_UNSET 2
#define CIL_DECOMPILER_TYPE_ALL   3

// CIL Decompiler Modes
#define CIL_DECOMPILER_MODE_X86    0
#define CIL_DECOMPILER_MODE_X86_64 1
#define CIL_DECOMPILER_MODE_UNSET  2

#define CIL_DECOMPILER_MAX_TRAITS 256
#define CIL_DECOMPILER_MAX_INSN   16384

// CIL Instructions
#define CIL_INS_ADD            0x58
#define CIL_INS_ADD_OVF        0xD6
#define CIL_INS_ADD_OVF_UN     0xD7
#define CIL_INS_AND            0x5F
#define CIL_INS_BEQ            0x3B
#define CIL_INS_BEQ_S          0x2E
#define CIL_INS_BGE            0x3C
#define CIL_INS_BGE_S          0x2F
#define CIL_INS_BGE_UN         0x41
#define CIL_INS_BGE_UN_S       0x34
#define CIL_INS_BGT            0x3D
#define CIL_INS_BGT_S          0x30
#define CIL_INS_BGT_UN         0x42
#define CIL_INS_BGT_UN_S       0x35
#define CIL_INS_BLE            0x3E
#define CIL_INS_BLE_S          0x31
#define CIL_INS_BLE_UN         0x43
#define CIL_INS_BLE_UN_S       0x36
#define CIL_INS_BLT            0x3F
#define CIL_INS_BLT_S          0x32
#define CIL_INS_BLT_UN         0x44
#define CIL_INS_BLT_UN_S       0x37
#define CIL_INS_BNE_UN         0x40
#define CIL_INS_BNE_UN_S       0x33
#define CIL_INS_BOX            0x8C
#define CIL_INS_BR             0x38
#define CIL_INS_BR_S           0x2B
#define CIL_INS_BREAK          0x01
#define CIL_INS_BRFALSE        0x39
#define CIL_INS_BRFALSE_S      0x2C
#define CIL_INS_BRINST         0x3A
#define CIL_INS_BRINST_S       0x2D
#define CIL_INS_BRNULL         0x39
#define CIL_INS_BRNULL_S       0x2C
#define CIL_INS_BRTRUE         0x3A
#define CIL_INS_BRTRUE_S       0x2D
#define CIL_INS_BRZERO         0x39
#define CIL_INS_BRZERO_S       0x2C
#define CIL_INS_CALL           0x28
#define CIL_INS_CALLI          0x29
#define CIL_INS_CALLVIRT       0x6F
#define CIL_INS_CASTCLASS      0x74
#define CIL_INS_CKINITE        0xC3
#define CIL_INS_CONV_I         0xD3
#define CIL_INS_CONV_I1        0x67
#define CIL_INS_CONV_I2        0x68
#define CIL_INS_CONV_I4        0x69
#define CIL_INS_CONV_I8        0x6A
#define CIL_INS_CONV_OVF_i     0xD4
#define CIL_INS_CONV_OVF_I_UN  0x8A
#define CIL_INS_CONV_OVF_I1    0xB3
#define CIL_INS_CONV_OVF_I1_UN 0x82
#define CIL_INS_CONV_OVF_I2    0xB5
#define CIL_INS_CONV_OVF_I2_UN 0x83
#define CIL_INS_CONV_OVF_I4    0xB7
#define CIL_INS_CONV_OVF_I4_UN 0x84
#define CIL_INS_CONV_OVF_I8    0xB9
#define CIL_INS_CONV_OVF_I8_UN 0x85
#define CIL_INS_CONV_OVF_U     0xD5
#define CIL_INS_CONV_OVF_U_UN  0x8B
#define CIL_INS_CONV_OVF_U1    0xB4
#define CIL_INS_CONV_OVF_U1_UN 0x86
#define CIL_INS_CONV_OVF_U2    0xB6
#define CIL_INS_CONV_OVF_U2_UN 0x87
#define CIL_INS_CONV_OVF_U4    0xB8
#define CIL_INS_CONV_OVF_U4_UN 0x88
#define CIL_INS_CONV_OVF_U8    0xBA
#define CIL_INS_CONV_OVF_U8_UN 0x89
#define CIL_INS_CONV_R_UN      0x76
#define CIL_INS_CONV_R4        0x6B
#define CIL_INS_CONV_R8        0x6C
#define CIL_INS_CONV_U         0xE0
#define CIL_INS_CONV_U1        0xD2
#define CIL_INS_CONV_U2        0xD1
#define CIL_INS_CONV_U4        0x6D
#define CIL_INS_CONV_U8        0x6E
#define CIL_INS_CPOBJ          0x70
#define CIL_INS_DIV            0x5B
#define CIL_INS_DIV_UN         0x5C
#define CIL_INS_DUP            0x25
#define CIL_INS_ENDFAULT       0xDC
#define CIL_INS_ENDFINALLY     0xDC
#define CIL_INS_ISINST         0x75
#define CIL_INS_JMP            0x27
#define CIL_INS_LDARG_0        0x02
#define CIL_INS_LDARG_1        0x03
#define CIL_INS_LDARG_2        0x04
#define CIL_INS_LDARG_3        0x05
#define CIL_INS_LDARG_S        0x0E
#define CIL_INS_LDARGA_S       0x0F
#define CIL_INS_LDC_I4         0x20
#define CIL_INS_LDC_I4_0       0x16
#define CIL_INS_LDC_I4_1       0x17
#define CIL_INS_LDC_I4_2       0x18
#define CIL_INS_LDC_I4_3       0x19
#define CIL_INS_LDC_I4_4       0x1A
#define CIL_INS_LDC_I4_5       0x1B
#define CIL_INS_LDC_I4_6       0x1C
#define CIL_INS_LDC_I4_7       0x1D
#define CIL_INS_LDC_I4_8       0x1E
#define CIL_INS_LDC_I4_M1      0x15
#define CIL_INS_LDC_I4_S       0x1F
#define CIL_INS_LDC_I8         0x21
#define CIL_INS_LDC_R4         0x22
#define CIL_INS_LDC_R8         0x23
#define CIL_INS_LDELM          0xA3
#define CIL_INS_LDELM_I        0x97
#define CIL_INS_LDELM_I1       0x90
#define CIL_INS_LDELM_I2       0x92
#define CIL_INS_LDELM_I4       0x94
#define CIL_INS_LDELM_I8       0x96
#define CIL_INS_LDELM_R4       0x98
#define CIL_INS_LDELM_R8       0x99
#define CIL_INS_LDELM_REF      0x9A
#define CIL_INS_LDELM_U1       0x91
#define CIL_INS_LDELM_U2       0x93
#define CIL_INS_LDELM_U4       0x95
#define CIL_INS_LDELM_U8       0x96
#define CIL_INS_LDELMA         0x8F
#define CIL_INS_LDFLD          0x7B
#define CIL_INS_LDFLDA         0x7C
#define CIL_INS_LDIND_I        0x4D
#define CIL_INS_LDIND_I1       0x46
#define CIL_INS_LDIND_I2       0x48
#define CIL_INS_LDIND_I4       0x4A
#define CIL_INS_LDIND_I8       0x4C
#define CIL_INS_LDIND_R4       0x4E
#define CIL_INS_LDIND_R8       0x4F
#define CIL_INS_LDIND_REF      0x50
#define CIL_INS_LDIND_U1       0x47
#define CIL_INS_LDIND_U2       0x49
#define CIL_INS_LDIND_U4       0x4B
#define CIL_INS_LDIND_U8       0x4C
#define CIL_INS_LDLEN          0x8E
#define CIL_INS_LDLOC_0        0x06
#define CIL_INS_LDLOC_1        0x07
#define CIL_INS_LDLOC_2        0x08
#define CIL_INS_LDLOC_3        0x09
#define CIL_INS_LDLOC_S        0x11
#define CIL_INS_LDLOCA_S       0x12
#define CIL_INS_LDNULL         0x14
#define CIL_INS_LDOBJ          0x71
#define CIL_INS_LDSFLD         0x7E
#define CIL_INS_LDSFLDA        0x7F
#define CIL_INS_LDSTR          0x72
#define CIL_INS_LDTOKEN        0xD0
#define CIL_INS_LEAVE          0xDD
#define CIL_INS_LEAVE_S        0xDE
#define CIL_INS_MKREFANY       0xC6
#define CIL_INS_MUL            0x5A
#define CIL_INS_MUL_OVF        0xD8
#define CIL_INS_MUL_OVF_UN     0xD9
#define CIL_INS_NEG            0x65
#define CIL_INS_NEWARR         0x8D
#define CIL_INS_NEWOBJ         0x73
#define CIL_INS_NOP            0x00
#define CIL_INS_NOT            0x66
#define CIL_INS_OR             0x60
#define CIL_INS_POP            0x26
#define CIL_INS_REFANYVAL      0xC2
#define CIL_INS_REM            0x5D
#define CIL_INS_REM_UN         0x5E
#define CIL_INS_RET            0x2A
#define CIL_INS_SHL            0x62
#define CIL_INS_SHR            0x63
#define CIL_INS_SHR_UN         0x64
#define CIL_INS_STARG_S        0x10
#define CIL_INS_STELEM         0xA4
#define CIL_INS_STELEM_I       0x9B
#define CIL_INS_STELEM_I1      0x9C
#define CIL_INS_STELEM_I2      0x9D
#define CIL_INS_STELEM_I4      0x9E
#define CIL_INS_STELEM_I8      0x9F
#define CIL_INS_STELEM_R4      0xA0
#define CIL_INS_STELEM_R8      0xA1
#define CIL_INS_STELEM_REF     0xA2
#define CIL_INS_STFLD          0x7D
#define CIL_INS_STIND_I        0xDF
#define CIL_INS_STIND_I1       0x52
#define CIL_INS_STIND_I2       0x53
#define CIL_INS_STIND_I4       0x54
#define CIL_INS_STIND_I8       0x55
#define CIL_INS_STIND_R4       0x56
#define CIL_INS_STIND_R8       0x57
#define CIL_INS_STIND_REF      0x51
#define CIL_INS_STLOC_0        0x0A
#define CIL_INS_STLOC_1        0x0B
#define CIL_INS_STLOC_2        0x0C
#define CIL_INS_STLOC_3        0x0D
#define CIL_INS_STOBJ          0x81
#define CIL_INS_STSFLD         0x80
#define CIL_INS_SUB            0x59
#define CIL_INS_SUB_OVF        0xDA
#define CIL_INS_SUB_OVF_UN     0xDB
#define CIL_INS_SWITCH         0x45
#define CIL_INS_THROW          0x7A
#define CIL_INS_UNBOX          0x79
#define CIL_INS_UNBOX_ANY      0xA5
#define CIL_INS_XOR            0x61
#define CIL_INS_STLOC_S        0x13

#define CIL_INS_PREFIX         0xFE
#define CIL_INS_ARGLIST        0x00
#define CIL_INS_CEQ            0x01
#define CIL_INS_CGT            0x02
#define CIL_INS_CGT_UN         0x03
#define CIL_INS_CLT            0x04
#define CIL_INS_CLT_UN         0x05
#define CIL_INS_CONSTRAINED    0x16
#define CIL_INS_CPBLK          0x17
#define CIL_INS_ENDFILTER      0x11
#define CIL_INS_INITBLK        0x18
#define CIL_INS_INITOBJ        0x15
#define CIL_INS_LDARG          0x09
#define CIL_INS_LDARGA         0x0A
#define CIL_INS_LDFTN          0x06
#define CIL_INS_LDLOC          0x0C
#define CIL_INS_LDLOCA         0x0D
#define CIL_INS_LDVIRTFTN      0x07
#define CIL_INS_LOCALLOC       0x0F
#define CIL_INS_NO             0x19
#define CIL_INS_READONLY       0x1E
#define CIL_INS_REFANYTYPE     0x1D
#define CIL_INS_RETHROW        0x1A
#define CIL_INS_SIZEOF         0x1C
#define CIL_INS_STARG          0x0B
#define CIL_INS_STLOC          0x0E
#define CIL_INS_TAIL           0x14
#define CIL_INS_UNALIGNED      0x12
#define CIL_INS_VOLATILE       0x13

class CILDecompiler {
    private:
        struct Traits {
            char *functions;
            char *blocks;
        };
        int mode = CIL_DECOMPILER_MODE_UNSET;
        int type = CIL_DECOMPILER_TYPE_UNSET;
        struct Instruction {
            uint16_t opcode;
            uint32_t operand;
        };
        char * hexdump_be(const void *data, int size){
            int buffer_size = size * 2 + size;
            char *buffer0 = (char *)malloc(buffer_size);
            memset((void *)buffer0, 0, buffer_size);
            const unsigned char * pc = (const unsigned char *)data;
            for (int i = 0; i < size; i++){
                sprintf(buffer0, "%s%02x", buffer0, pc[i]);
            }
            return buffer0;
        }
    public:
        struct Traits traits[CIL_DECOMPILER_MAX_TRAITS];
        CILDecompiler(){
            for (int i = 0; i < CIL_DECOMPILER_MAX_TRAITS; i++){
                traits[i].functions = NULL;
                traits[i].blocks = NULL;
            }
        }
        bool Setup(cs_mode input_mode, int input_type){
            switch(input_mode){
                case CS_MODE_32:
                    mode = CIL_DECOMPILER_MODE_X86;
                    break;
                case CS_MODE_64:
                    mode = mode = CIL_DECOMPILER_MODE_X86_64;
                    break;
                default:
                    fprintf(stderr, "[x] unsupported CIL decompiler mode\n");
                    mode = CIL_DECOMPILER_MODE_UNSET;
                    return false;
            }
            switch(input_type){
                case CIL_DECOMPILER_TYPE_ALL:
                    type = CIL_DECOMPILER_TYPE_ALL;
                    break;
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
        bool x86(void *data, int data_size, int index){
            const unsigned char *pc = (const unsigned char *)data;
            char *bytes = NULL;
            for (int i = 0; i < data_size; i++){
                int operand_size = 0;
                //printf("0x%02x\n", pc[i]);
                if (pc[i] == CIL_INS_PREFIX){
                    i++;
                    switch(pc[i]){
                        case CIL_INS_CEQ:
                            printf("ceq\n");
                            break;
                        case CIL_INS_ARGLIST:
                            printf("arglist\n");
                            break;
                        case CIL_INS_CGT:
                            printf("cgt\n");
                            break;
                        case CIL_INS_CLT_UN:
                            printf("clt.un\n");
                            break;
                        case CIL_INS_CONSTRAINED:
                            printf("constrained ");
                            operand_size = 32;
                            break;
                        case CIL_INS_CPBLK:
                            printf("cpblk\n");
                            break;
                        case CIL_INS_ENDFILTER:
                            printf("endfilter\n");
                            break;
                        case CIL_INS_INITBLK:
                            printf("initblk\n");
                            break;
                        case CIL_INS_INITOBJ:
                            printf("initobj ");
                            operand_size = 32;
                            break;
                        case CIL_INS_LDARG:
                            printf("ldarg ");
                            operand_size = 16;
                            break;
                        case CIL_INS_LDARGA:
                            printf("ldarga ");
                            operand_size = 16;
                            break;
                        case CIL_INS_LDFTN:
                            bytes = hexdump_be(&pc[i-1], 6);
                            printf("0x%x\t\t%s\tldftn \t\t", i, bytes);
                            free(bytes);
                            operand_size = 32;
                            break;
                        case CIL_INS_LDLOC:
                            printf("ldloc ");
                            operand_size = 16;
                            break;
                        case CIL_INS_LDLOCA:
                            printf("ldloca ");
                            operand_size = 16;
                            break;
                        case CIL_INS_LDVIRTFTN:
                            printf("ldvirtftn ");
                            operand_size = 32;
                            break;
                        case CIL_INS_LOCALLOC:
                            printf("localloc\n");
                            break;
                        case CIL_INS_NO:
                            printf("no\n");
                            break;
                        case CIL_INS_READONLY:
                            printf("readonly ");
                            operand_size = 32;
                            break;
                        case CIL_INS_REFANYTYPE:
                            printf("refanytype\n");
                            break;
                        case CIL_INS_RETHROW:
                            printf("rethrow\n");
                            break;
                        case CIL_INS_SIZEOF:
                            printf("sizeof ");
                            operand_size = 32;
                            break;
                        case CIL_INS_STARG:
                            printf("starg ");
                            operand_size = 16;
                            break;
                        case CIL_INS_STLOC:
                            printf("stloc ");
                            operand_size = 16;
                            break;
                        case CIL_INS_TAIL:
                            printf("tail\n");
                            break;
                        case CIL_INS_UNALIGNED:
                            printf("unaligned\n");
                            break;
                        case CIL_INS_VOLATILE:
                            printf("volatile ");
                            operand_size = 32;
                            break;
                        default:
                            fprintf(stderr, "[x] unknown opcode 0x%02x at offset %d\n", pc[i], i);
                            return false;
                    }
                } else {
                    switch(pc[i]){
                        case CIL_INS_ADD:
                            printf("0x%x\t\t%02x\t\tadd\n", i, pc[i]);
                            break;
                        case CIL_INS_ADD_OVF:
                            printf("0x%x\t\t%02x\t\tadd.ovf\n", i, pc[i]);
                            break;
                        case CIL_INS_ADD_OVF_UN:
                            printf("0x%x\t\t%02x\t\tadd.ovf.un\n", i , pc[i]);
                            break;
                        case CIL_INS_AND:
                            printf("0x%x\t\t%02x\t\tand\n", i, pc[i]);
                            break;
                        case CIL_INS_BEQ:
                            bytes = hexdump_be(&pc[i], 5);
                            printf("0x%x\t\t%s\t\tbeq ", i, bytes);
                            free(bytes);
                            operand_size = 32;
                            break;
                        case CIL_INS_BEQ_S:
                            printf("beq.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BGE:
                            printf("bge ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BGE_S:
                            printf("bge.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BGE_UN:
                            bytes = hexdump_be(&pc[i], 5);
                            printf("0x%x\t\t%s\tbge.un \t\t", i, bytes);
                            free(bytes);
                            operand_size = 32;
                            break;
                        case CIL_INS_BGE_UN_S:
                            bytes = hexdump_be(&pc[i], 2);
                            printf("0x%x\t\t%s\t\tbge.un.s \t", i, bytes);
                            free(bytes);
                            operand_size = 8;
                            break;
                        case CIL_INS_BGT:
                            printf("bgt ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BGT_S:
                            printf("bgt.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BGT_UN:
                            printf("bgt.un ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BGT_UN_S:
                            printf("bgt.un.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BLE:
                            printf("ble ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BLE_S:
                            printf("ble.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BLE_UN:
                            printf("ble.un ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BLE_UN_S:
                            printf("ble.un.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BLT:
                            printf("blt ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BLT_S:
                            printf("blt.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BLT_UN:
                            printf("blt.un ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BLT_UN_S:
                            printf("blt.un.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BNE_UN:
                            printf("bne.un ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BNE_UN_S:
                            printf("bne.un.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BOX:
                            printf("box ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BR:
                            printf("br ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BR_S:
                            printf("br.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_BREAK:
                            printf("break\n");
                            break;
                        case CIL_INS_BRFALSE:
                            printf("brfalse ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BRFALSE_S:
                            printf("brfalse.s ");
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
                            printf("brtrue ");
                            operand_size = 32;
                            break;
                        case CIL_INS_BRTRUE_S:
                            printf("brtrue.s ");
                            operand_size = 8;
                            break;
                        // case CIL_INS_BRZERO:
                        //     printf("brzero\n");
                        //     break;
                        // case CIL_INS_BRZERO_S:
                        //     printf("brzero.s\n");
                        //     break;
                        case CIL_INS_CALL:
                            printf("call ");
                            operand_size = 32;
                            break;
                        case CIL_INS_CALLI:
                            printf("calli ");
                            operand_size = 32;
                            break;
                        case CIL_INS_CALLVIRT:
                            printf("callvirt ");
                            operand_size = 32;
                            break;
                        case CIL_INS_CASTCLASS:
                            printf("castclass ");
                            operand_size = 32;
                            break;
                        case CIL_INS_CKINITE:
                            printf("ckinite\n");
                            break;
                        case CIL_INS_CONV_I:
                            printf("conv.i");
                            break;
                        case CIL_INS_CONV_I1:
                            printf("conv.i1\n");
                            break;
                        case CIL_INS_CONV_I2:
                            printf("conv.i2\n");
                            break;
                        case CIL_INS_CONV_I4:
                            printf("conv.i4\n");
                            break;
                        case CIL_INS_CONV_I8:
                            printf("conv.i8\n");
                            break;
                        case CIL_INS_CONV_OVF_i:
                            printf("conv.ovf.i\n");
                            break;
                        case CIL_INS_CONV_OVF_I_UN:
                            printf("conv.ovf.i.un\n");
                            break;
                        case CIL_INS_CONV_OVF_I1:
                            printf("conv.ovf.i1\n");
                            break;
                        case CIL_INS_CONV_OVF_I1_UN:
                            printf("conv.ovf.i1.un\n");
                            break;
                        case CIL_INS_CONV_OVF_I2:
                            printf("conv.ovf.i2\n");
                            break;
                        case CIL_INS_CONV_OVF_I2_UN:
                            printf("conv.ovf.i2.un\n");
                            break;
                        case CIL_INS_CONV_OVF_I4:
                            printf("conv.ovf.i4\n");
                            break;
                        case CIL_INS_CONV_OVF_I4_UN:
                            printf("conv.ovf.i4.un\n");
                            break;
                        case CIL_INS_CONV_OVF_I8:
                            printf("conv.ovf.i8\n");
                            break;
                        case CIL_INS_CONV_OVF_I8_UN:
                            printf("conv.ovf.i8.un\n");
                            break;
                        case CIL_INS_CONV_OVF_U:
                            printf("conv.ovf.u\n");
                            break;
                        case CIL_INS_CONV_OVF_U_UN:
                            printf("conv.ovf.u.un\n");
                            break;
                        case CIL_INS_CONV_OVF_U1:
                            printf("conv.ovf.u1\n");
                            break;
                        case CIL_INS_CONV_OVF_U1_UN:
                            printf("conv.ovf.u1.un\n");
                            break;
                        case CIL_INS_CONV_OVF_U2:
                            printf("conv.ovf.u2\n");
                            break;
                        case CIL_INS_CONV_OVF_U2_UN:
                            printf("conv.ovf.u2.un\n");
                            break;
                        case CIL_INS_CONV_OVF_U4:
                            printf("conv.ovf.u4\n");
                            break;
                        case CIL_INS_CONV_OVF_U4_UN:
                            printf("conv.ovf.u4.un\n");
                            break;
                        case CIL_INS_CONV_OVF_U8:
                            printf("conv.ovf.u8\n");
                            break;
                        case CIL_INS_CONV_OVF_U8_UN:
                            printf("conv.ovf.u8.un\n");
                            break;
                        case CIL_INS_CONV_R_UN:
                            printf("conv.r.un\n");
                            break;
                        case CIL_INS_CONV_R4:
                            printf("conv.r4\n");
                            break;
                        case CIL_INS_CONV_R8:
                            printf("conv.r8\n");
                            break;
                        case CIL_INS_CONV_U:
                            printf("conv.u\n");
                            break;
                        case CIL_INS_CONV_U1:
                            printf("conv.u1\n");
                            break;
                        case CIL_INS_CONV_U2:
                            printf("conv.u2\n");
                            break;
                        case CIL_INS_CONV_U4:
                            printf("conv.u4\n");
                            break;
                        case CIL_INS_CONV_U8:
                            printf("conv.u8\n");
                            break;
                        case CIL_INS_CPOBJ:
                            printf("cpobj ");
                            operand_size = 32;
                            break;
                        case CIL_INS_DIV:
                            printf("div\n");
                            break;
                        case CIL_INS_DIV_UN:
                            printf("div.un\n");
                            break;
                        case CIL_INS_DUP:
                            printf("dup\n");
                            break;
                        // case CIL_INS_ENDFAULT:
                        //     printf("endfault\n");
                        //     break;
                        case CIL_INS_ENDFINALLY:
                            printf("endfinally\n");
                            break;
                        case CIL_INS_ISINST:
                            printf("isinst ");
                            operand_size = 32;
                            break;
                        case CIL_INS_JMP:
                            printf("jmp ");
                            operand_size = 32;
                            break;
                        case CIL_INS_LDARG_0:
                            printf("ldarg.0\n");
                            break;
                        case CIL_INS_LDARG_1:
                            printf("ldarg.1\n");
                            break;
                        case CIL_INS_LDARG_2:
                            printf("ldarg.2\n");
                            break;
                        case CIL_INS_LDARG_3:
                            printf("ldarg.3\n");
                            break;
                        case CIL_INS_LDARG_S:
                            printf("ldarg.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_LDARGA_S:
                            printf("ldarga.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_LDC_I4:
                            printf("ldc.i4 ");
                            operand_size = 32;
                            break;
                        case CIL_INS_LDC_I4_0:
                            printf("ldc.i4.0\n");
                            break;
                        case CIL_INS_LDC_I4_1:
                            printf("ldc.i4.1\n");
                            break;
                        case CIL_INS_LDC_I4_2:
                            printf("ldc.i4.2\n");
                            break;
                        case CIL_INS_LDC_I4_3:
                            printf("ldc.i4.3\n");
                            break;
                        case CIL_INS_LDC_I4_4:
                            printf("ldc.i4.4\n");
                            break;
                        case CIL_INS_LDC_I4_5:
                            printf("ldc.i4.5\n");
                            break;
                        case CIL_INS_LDC_I4_6:
                            printf("ldc.i4.6\n");
                            break;
                        case CIL_INS_LDC_I4_7:
                            printf("ldc.i4.7\n");
                            break;
                        case CIL_INS_LDC_I4_8:
                            printf("ldc.i4.8\n");
                            break;
                        case CIL_INS_LDC_I4_M1:
                            printf("ldc.i4.m1\n");
                            break;
                        case CIL_INS_LDC_I4_S:
                            printf("ldc.i4.s ");
                            operand_size = 8;
                            break;
                        case CIL_INS_LDC_I8:
                            printf("ldc.i8 ");
                            operand_size = 64;
                            break;
                        case CIL_INS_LDC_R4:
                            printf("ldc.r4 ");
                            operand_size = 32;
                            break;
                        case CIL_INS_LDC_R8:
                            printf("ldc.r8 ");
                            operand_size = 64;
                            break;
                        case CIL_INS_LDELM:
                            printf("ldelm ");
                            operand_size = 32;
                            break;
                        case CIL_INS_LDELM_I:
                            printf("ldelm.i\n");
                            break;
                        case CIL_INS_LDELM_I1:
                            printf("ldelm.i1\n");
                            break;
                        case CIL_INS_LDELM_I2:
                            printf("ldelm.i2\n");
                            break;
                        case CIL_INS_LDELM_I4:
                            printf("ldelm.i4\n");
                            break;
                        case CIL_INS_LDELM_I8:
                            printf("ldelm.i8\n");
                            break;
                        case CIL_INS_LDELM_R4:
                            printf("ldelm.r4\n");
                            break;
                        case CIL_INS_LDELM_R8:
                            printf("ldelm.r8\n");
                            break;
                        case CIL_INS_LDELM_REF:
                            printf("ldelm.ref\n");
                            break;
                        case CIL_INS_LDELM_U1:
                            printf("ldelm.u1\n");
                            break;
                        case CIL_INS_LDELM_U2:
                            printf("ldelm.u2\n");
                            break;
                        case CIL_INS_LDELM_U4:
                            printf("ldelm.u4\n");
                            break;
                        // case CIL_INS_LDELM_U8:
                        //     printf("ldelm.u8\n");
                        //     break;
                        case CIL_INS_LDELMA:
                            printf("ldelma ");
                            operand_size = 32;
                            break;
                        case CIL_INS_LDFLD:
                            printf("ldfld ");
                            operand_size = 32;
                            break;
                        case CIL_INS_LDFLDA:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tldflda ", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_LDIND_I:
                            printf("0x%x\t\t%02x\t\tldind.i\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_I1:
                            printf("0x%x\t\t%02x\t\tldind.i1\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_I2:
                            printf("0x%x\t\t%02x\t\tldind.i2\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_I4:
                            printf("0x%x\t\t%02x\t\tldind.i4\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_I8:
                            printf("0x%x\t\t%02x\t\tldind.i8\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_R4:
                            printf("0x%x\t\t%02x\t\tldind.r4\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_R8:
                            printf("0x%x\t\t%02x\t\tldind.r8\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_REF:
                            printf("0x%x\t\t%02x\t\tldind.ref\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_U1:
                            printf("0x%x\t\t%02x\t\tldind.u1\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_U2:
                            printf("0x%x\t\t%02x\t\tldind.u2\n", i, pc[i]);
                            break;
                        case CIL_INS_LDIND_U4:
                            printf("0x%x\t\t%02x\t\tldind.u4\n", i, pc[i]);
                            break;
                        // case CIL_INS_LDIND_U8:
                        //     printf("ldind.u8\n");
                        //     break;
                        case CIL_INS_LDLEN:
                            printf("0x%x\t\t%02x\t\tldlen\n", i, pc[i]);
                            break;
                        case CIL_INS_LDLOC_0:
                            printf("0x%x\t\t%02x\t\tldloc.0\n", i, pc[i]);
                            break;
                        case CIL_INS_LDLOC_1:
                            printf("0x%x\t\t%02x\t\tldloc.1\n", i, pc[i]);
                            break;
                        case CIL_INS_LDLOC_2:
                            printf("0x%x\t\t%02x\t\tldloc.2\n", i, pc[i]);
                            break;
                        case CIL_INS_LDLOC_3:
                            printf("0x%x\t\t%02x\t\tldloc.3\n", i, pc[i]);
                            break;
                        case CIL_INS_LDLOC_S:
                            operand_size = 8;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\t\tldloc.s \t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_LDLOCA_S:
                            operand_size = 8;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\t\tldloca.s \t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_LDNULL:
                            printf("0x%x\t\t%02x\t\tldnull\n", i, pc[i]);
                            break;
                        case CIL_INS_LDOBJ:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tldobj \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_LDSFLD:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tldsfld \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_LDSFLDA:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tldsflda \t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_LDSTR:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tldstr \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_LDTOKEN:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tldtoken \t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_LEAVE:
                            bytes = hexdump_be(&pc[i], 5);
                            printf("0x%x\t\t%s\tleave \t\t", i, bytes);
                            free(bytes);
                            operand_size = 32;
                            break;
                        case CIL_INS_LEAVE_S:
                            bytes = hexdump_be(&pc[i], 2);
                            printf("0x%x\t\t%s\t\tleave.s \t", i, bytes);
                            free(bytes);
                            operand_size = 8;
                            break;
                        case CIL_INS_MKREFANY:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tmkrefany \t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_MUL:
                            printf("0x%x\t\t%02x\t\tmul\n", i, pc[i]);
                            break;
                        case CIL_INS_MUL_OVF:
                            printf("0x%x\t\t%02x\t\tmul.ovf\n", i, pc[i]);
                            break;
                        case CIL_INS_MUL_OVF_UN:
                            printf("0x%x\t\t%02x\t\tmul.ovf.un\n", i, pc[i]);
                            break;
                        case CIL_INS_NEG:
                            printf("0x%x\t\t%02x\t\tneg\n", i, pc[i]);
                            break;
                        case CIL_INS_NEWARR:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tnewarr \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_NEWOBJ:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tnewobj \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_NOP:
                            printf("0x%x\t\t%02x\t\tnop\n", i, pc[i]);
                            break;
                        case CIL_INS_NOT:
                            printf("0x%x\t\t%02x\t\tnot\n", i, pc[i]);
                            break;
                        case CIL_INS_OR:
                            printf("0x%x\t\t%02x\t\tor\n", i, pc[i]);
                            break;
                        case CIL_INS_POP:
                            printf("0x%x\t\t%02x\t\tpop\n", i, pc[i]);
                            break;
                        case CIL_INS_REFANYVAL:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\trefanyval \t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_REM:
                            printf("0x%x\t\t%02x\t\trem\n", i, pc[i]);
                            break;
                        case CIL_INS_REM_UN:
                            printf("0x%x\t\t%02x\t\trem.un\n", i, pc[i]);
                            break;
                        case CIL_INS_RET:
                            printf("0x%x\t\t%02x\t\tret\n", i, pc[i]);
                            break;
                        case CIL_INS_SHL:
                            printf("0x%x\t\t%02x\t\tshl\n", i, pc[i]);
                            break;
                        case CIL_INS_SHR:
                            printf("0x%x\t\t%02x\t\tshr\n", i, pc[i]);
                            break;
                        case CIL_INS_SHR_UN:
                            printf("0x%x\t\t%02x\t\tshr.un\n", i, pc[i]);
                            break;
                        case CIL_INS_STARG_S:
                            operand_size = 8;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\t\tstarg.s \t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_STELEM:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tstelm \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_STELEM_I:
                            printf("0x%x\t\t%02x\t\tstelm.i\n", i, pc[i]);
                            break;
                        case CIL_INS_STELEM_I1:
                            printf("0x%x\t\t%02x\t\tstelm.i1\n", i, pc[i]);
                            break;
                        case CIL_INS_STELEM_I2:
                            printf("0x%x\t\t%02x\t\tstelm.i2\n", i, pc[i]);
                            break;
                        case CIL_INS_STELEM_I4:
                            printf("0x%x\t\t%02x\t\tstelm.i4\n", i, pc[i]);
                            break;
                        case CIL_INS_STELEM_I8:
                            printf("0x%x\t\t%02x\t\tstelm.i8\n", i, pc[i]);
                            break;
                        case CIL_INS_STELEM_R4:
                            printf("0x%x\t\t%02x\t\tstelm.r4\n", i, pc[i]);
                            break;
                        case CIL_INS_STELEM_R8:
                            printf("0x%x\t\t%02x\t\tstelm.r8\n", i, pc[i]);
                            break;
                        case CIL_INS_STELEM_REF:
                            printf("0x%x\t\t%02x\t\tstelm.ref\n", i, pc[i]);
                            break;
                        case CIL_INS_STFLD:
                            printf("0x%x\t\t%02x\t\tstfld\n", i, pc[i]);
                            break;
                        case CIL_INS_STIND_I:
                            printf("0x%x\t\t%02x\t\tstind.i\n", i, pc[i]);
                            break;
                        case CIL_INS_STIND_I1:
                            printf("0x%x\t\t%02x\t\tstind.i1\n", i, pc[i]);
                            break;
                        case CIL_INS_STIND_I2:
                            printf("0x%x\t\t%02x\t\tstind.i2\n", i, pc[i]);
                            break;
                        case CIL_INS_STIND_I4:
                            printf("0x%x\t\t%02x\t\tstind.i4\n", i, pc[i]);
                            break;
                        case CIL_INS_STIND_I8:
                            printf("0x%x\t\t%02x\t\tstind.i8\n", i, pc[i]);
                            break;
                        case CIL_INS_STIND_R4:
                            printf("0x%x\t\t%02x\t\tstind.r4\n", i, pc[i]);
                            break;
                        case CIL_INS_STIND_R8:
                            printf("0x%x\t\t%02x\t\tstind.r8\n", i, pc[i]);
                            break;
                        case CIL_INS_STIND_REF:
                            printf("0x%x\t\t%02x\t\tstind.ref\n", i, pc[i]);
                            break;
                        case CIL_INS_STLOC_S:
                            bytes = hexdump_be(&pc[i], 2);
                            printf("0x%x\t\t%s\t\tstloc.s \t", i, bytes);
                            free(bytes);
                            operand_size = 8;
                            break;
                        case CIL_INS_STLOC_0:
                            printf("0x%x\t\t%02x\t\tstloc.0\n", i, pc[i]);
                            break;
                        case CIL_INS_STLOC_1:
                            printf("0x%x\t\t%02x\t\tstloc.1\n", i, pc[i]);
                            break;
                        case CIL_INS_STLOC_2:
                            printf("0x%x\t\t%02x\t\tstloc.2\n", i, pc[i]);
                            break;
                        case CIL_INS_STLOC_3:
                            printf("0x%x\t\t%02x\t\tstloc.3\n", i, pc[i]);
                            break;
                        case CIL_INS_STOBJ:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tstobj \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_STSFLD:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tstsfld \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_SUB:
                            printf("0x%x\t\t%02x\t\tsub\n", i, pc[i]);
                            break;
                        case CIL_INS_SUB_OVF:
                            printf("0x%x\t\t%02x\t\tsub.ovf\n", i, pc[i]);
                            break;
                        case CIL_INS_SUB_OVF_UN:
                            printf("0x%x\t\t%02x\t\tsub.ovf.un\n", i, pc[i]);
                            break;
                        case CIL_INS_SWITCH:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tswitch \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_THROW:
                            printf("0x%x\t\t%02x\t\tthrow\n", i, pc[i]);
                            break;
                        case CIL_INS_UNBOX:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tunbox \t\t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_UNBOX_ANY:
                            operand_size = 32;
                            bytes = hexdump_be(&pc[i], (operand_size/8)+1);
                            printf("0x%x\t\t%s\tunbox.any \t", i, bytes);
                            free(bytes);
                            break;
                        case CIL_INS_XOR:
                            printf("0x%x\t\t%02x\t\txor\n", i, pc[i]);
                            break;
                        default:
                            fprintf(stderr, "[x] unknown opcode 0x%02x at offset %d\n", pc[i], i);
                            return false;
                    }
                }
                switch(operand_size){
                    case 0:
                        break;
                    case 8:
                        printf("0x%01x\n", pc[i+1]);
                        i++;
                        break;
                    case 16:
                        printf("0x%02x\n", pc[i+1]);
                        i = i + 2;
                        break;
                    case 32:
                        bytes = hexdump_be(&pc[i+1], 4);
                        printf("0x%s\n", bytes);
                        free(bytes);
                        i = i + 4;
                        break;
                    case 64:
                        bytes = hexdump_be(&pc[i+1], 8);
                        printf("0x%s\n", bytes);
                        free(bytes);
                        i = i + 8;
                        break;
                    default:
                        fprintf(stderr, "[x] unknown operand size %d\n", operand_size);
                }
            }
            return true;
        }
        ~CILDecompiler(){
            for (int i = 0; i < CIL_DECOMPILER_MAX_TRAITS; i++){
                if (traits[i].functions != NULL){
                    free(traits[i].functions);
                }
                if (traits[i].blocks != NULL){
                    free(traits[i].blocks);
                }
            }
        }
};

#endif
