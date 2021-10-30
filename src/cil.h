#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <assert.h>
#include <capstone/capstone.h>

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

// CIL Instructions
#define CIL_INS_ADD            0x58
#define CIL_INS_ADD_OVF        0xD6
#define CIL_INS_ADD_OVF_UN     0xD7
#define CIL_INS_AND            0x5F
#define CIL_INS_ARGLIST        0xFE00
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
#define CIL_INS_CEQ            0xFE01
#define CIL_INS_CGT            0xFE02
#define CIL_INS_CGT_UN         0xFE03
#define CIL_INS_CKINITE        0xC3
#define CIL_INS_CLT            0xFE04
#define CIL_INS_CLT_UN         0xFE05
#define CIL_INS_CONSTRAINED    0xFE16
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
#define CIL_INS_CPBLK          0xFE17
#define CIL_INS_CPOBJ          0x70
#define CIL_INS_DIV            0x5B
#define CIL_INS_DIV_UN         0x5C
#define CIL_INS_DUP            0x25
#define CIL_INS_ENDFAULT       0xDC
#define CIL_INS_ENDFILTER      0xFE11
#define CIL_INS_ENDFINALLY     0xDC
#define CIL_INS_INITBLK        0xFE18
#define CIL_INS_INITOBJ        0xFE15
#define CIL_INS_ISINST         0x75
#define CIL_INS_JMP            0x27
#define CIL_INS_LDARG          0xFE09
#define CIL_INS_LDARG_0        0x02
#define CIL_INS_LDARG_1        0x03
#define CIL_INS_LDARG_2        0x04
#define CIL_INS_LDARG_3        0x05
#define CIL_INS_LDARG_S        0x0E
#define CIL_INS_LDARGA         0xFE0A
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
#define CIL_INS_LDFTN          0xFE06
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
#define CIL_INS_LDLOC          0xFE0C
#define CIL_INS_LDLOC_0        0x06
#define CIL_INS_LDLOC_1        0x07
#define CIL_INS_LDLOC_2        0x08
#define CIL_INS_LDLOC_3        0x09
#define CIL_INS_LDLOC_S        0x11
#define CIL_INS_LDLOCA         0xFE0D
#define CIL_INS_LDLOCA_S       0x12
#define CIL_INS_LDNULL         0x14
#define CIL_INS_LDOBJ          0x71
#define CIL_INS_LDSFLD         0x7E
#define CIL_INS_LDSFLDA        0x7F
#define CIL_INS_LDSTR          0x72
#define CIL_INS_LDTOKEN        0xD0
#define CIL_INS_LDVIRTFTN      0xFE07
#define CIL_INS_LEAVE          0xDD
#define CIL_INS_LEAVE_S        0xDE
#define CIL_INS_LOCALLOC       0xFE0F
#define CIL_INS_MKREFANY       0xC6
#define CIL_INS_MUL            0x5A
#define CIL_INS_MUL_OVF        0xD8
#define CIL_INS_MUL_OVF_UN     0xD9
#define CIL_INS_NEG            0x65
#define CIL_INS_NEWARR         0x8D
#define CIL_INS_NEWOBJ         0x73
#define CIL_INS_NO             0xFE19
#define CIL_INS_NOP            0x00
#define CIL_INS_NOT            0x66
#define CIL_INS_OR             0x60
#define CIL_INS_POP            0x26
#define CIL_INS_READONLY       0xFE1E
#define CIL_INS_REFANYTYPE     0xFE1D
#define CIL_INS_REFANYVAL      0xC2
#define CIL_INS_REM            0x5D
#define CIL_INS_REM_UN         0x5E
#define CIL_INS_RET            0x2A
#define CIL_INS_RETHROW        0xFE1A
#define CIL_INS_SHL            0x62
#define CIL_INS_SHR            0x63
#define CIL_INS_SHR_UN         0x64
#define CIL_INS_SIZEOF         0xFE1C
#define CIL_INS_STARG          0xFE0B
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
#define CIL_INS_STLOC          0xFE0E
#define CIL_INS_STLOC_0        0x0A
#define CIL_INS_STLOC_1        0x0B
#define CIL_INS_STLOC_2        0x0C
#define CIL_INS_STLOC_3        0x0D
#define CIL_INS_STLOC_4        0x13
#define CIL_INS_STOBJ          0x81
#define CIL_INS_STSFLD         0x80
#define CIL_INS_SUB            0x59
#define CIL_INS_SUB_OVF        0xDA
#define CIL_INS_SUB_OVF_UN     0xDB
#define CIL_INS_SWITCH         0x45
#define CIL_INS_TAIL           0xFE14
#define CIL_INS_THROW          0x7A
#define CIL_INS_UNALIGNED      0xFE12
#define CIL_INS_UNBOX          0x79
#define CIL_INS_UNBOX_ANY      0xA5
#define CIL_INS_VOLATILE       0xFE13
#define CIL_INS_XOR            0x61

class CILDecompiler {
    private:
        struct Traits {
            char *functions;
            char *blocks;
        };
        int mode = CIL_DECOMPILER_MODE_UNSET;
        int type = CIL_DECOMPILER_TYPE_UNSET;
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
        void x86(void *data, int data_size, int index){
            const unsigned char *pc = (const unsigned char *)data
            for (int i = 0; i < data_size; i++){
                switch(pc[i]){
                    case CIL_INS_LDFTN:
                        printf("ldftn\n");
                        i = i + 4;
                        break;
                    case CIL_INS_STLOC:
                        printf("stloc\n");
                        i = i + 4;
                        break;
                }
            }
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
