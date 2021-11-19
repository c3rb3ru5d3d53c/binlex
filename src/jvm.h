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

#ifndef JVM_H
#define JVM_H

#define JVM_DECOMPILER_TYPE_BLCKS 0
#define JVM_DECOMPILER_TYPE_FUNCS 1
#define JVM_DECOMPILER_TYPE_UNSET 2

#define JVM_DECOMPILER_MAX_SECTIONS 256

#define JVM_INS_AALOAD      0x32
#define JVM_INS_AASTORE     0x53
#define JVM_INS_ACONST_NULL 0x01
#define JVM_INS_ALOAD       0x19
#define JVM_INS_ALOAD_0     0x2a
#define JVM_INS_ALOAD_1     0x2b
#define JVM_INS_ALOAD_2     0x2c
#define JVM_INS_ALOAD_3     0x2d
#define JVM_INS_ANEWARRAY   0xbd
#define JVM_INS_ARETURN     0xb0
#define JVM_INS_ARRAYLENGTH 0xbe
#define JVM_INS_ASTORE      0x3a
#define JVM_INS_ASTORE_0    0x4b
#define JVM_INS_ASTORE_1    0x4c
#define JVM_INS_ASTORE_2    0x4d
#define JVM_INS_ASTORE_3    0x4e
#define JVM_INS_ATHROW      0xbf
#define JVM_INS_BALOAD      0x33
#define JVM_INS_BASTORE     0x54
#define JVM_INS_BIPUSH      0x10
#define JVM_INS_BREAKPOINT  0xca
#define JVM_INS_CALOAD      0x34
#define JVM_INS_CASTORE     0x55
#define JVM_INS_CHECKCAST   0xc0
#define JVM_INS_D2F         0x90
#define JVM_INS_D2I         0x8e
#define JVM_INS_D2L         0x8f
#define JVM_INS_DADD        0x63
#define JVM_INS_DALOAD      0x31
#define JVM_INS_DASTORE     0x52
#define JVM_INS_DCMPG       0x98
#define JVM_INS_DCMPL       0x97
#define JVM_INS_DCONST_0    0x0e
#define JVM_INS_DCONST_1    0x0f
#define JVM_INS_DDIV        0x6f
#define JVM_INS_DLOAD       0x18
#define JVM_INS_DLOAD_0     0x26
#define JVM_INS_DLOAD_1     0x27
#define JVM_INS_DLOAD_2     0x28
#define JVM_INS_DLOAD_3     0x29
#define JVM_INS_DMUL        0x6b
#define JVM_INS_DNEG        0x77
#define JVM_INS_DREM        0x73
#define JVM_INS_DRETURN     0xaf
#define JVM_INS_DSTORE      0x39
#define JVM_INS_DSTORE_0    0x47
#define JVM_INS_DSTORE_1    0x48
#define JVM_INS_DSTORE_2    0x49
#define JVM_INS_DSTORE_3    0x4a
#define JVM_INS_DSUB        0x67
#define JVM_INS_DUP         0x59
#define JVM_INS_DUP_X1      0x5a
#define JVM_INS_DUP_X2      0x5e
#define JVM_INS_F2D         0x8d
#define JVM_INS_F2I         0x8b
#define JVM_INS_F2L         0x8c
#define JVM_INS_FADD        0x62
#define JVM_INS_FALOAD      0x30
#define JVM_INS_FASTORE     0x51
#define JVM_INS_FCMPG       0x96
#define JVM_INS_FCMPL       0x95
#define JVM_INS_FCONST_0    0x0b
#define JVM_INS_FCONST_1    0x0c
#define JVM_INS_FCONST_2    0x0d
#define JVM_INS_FDIV        0x6e
#define JVM_INS_FLOAD       0x17
#define JVM_INS_FLOAD_0     0x22
#define JVM_INS_FLOAD_1     0x23
#define JVM_INS_FLOAD_2     0x24
#define JVM_INS_FLOAD_3     0x25
#define JVM_INS_FMUL        0x6a
#define JVM_INS_FNEG        0x76
#define JVM_INS_FREM        0x72
#define JVM_INS_FRETURN     0xae
#define JVM_INS_FSTORE      0x38
#define JVM_INS_FSTORE_0    0x43
#define JVM_INS_FSTORE_1    0x44
#define JVM_INS_FSTORE_2    0x45
#define JVM_INS_FSTORE_3    0x46
#define JVM_INS_FSUB        0x66
#define JVM_INS_GETFIELD    0xb4
#define JVM_INS_GETSTATIC   0xb2
#define JVM_INS_GOTO        0xa7
#define JVM_INS_GOTO_W      0xc8
#define JVM_INS_I2B         0x91
#define JVM_INS_I2C         0x92
#define JVM_INS_I2D         0x87
#define JVM_INS_I2F         0x86
#define JVM_INS_I2L             0x85
#define JVM_INS_I2S             0x93
#define JVM_INS_IADD            0x60
#define JVM_INS_IALOAD          0x2e
#define JVM_INS_IAND            0x7e
#define JVM_INS_IASTORE         0x4f
#define JVM_INS_ICONST_M1       0x02
#define JVM_INS_ICONST_0        0x03
#define JVM_INS_ICONST_1        0x04
#define JVM_INS_ICONST_2        0x05
#define JVM_INS_ICONST_3        0x06
#define JVM_INS_ICONST_4        0x07
#define JVM_INS_ICONST_5        0x08
#define JVM_INS_IDIV            0x6c
#define JVM_INS_IF_ACMPEQ       0xa5
#define JVM_INS_IF_ACMPNE       0xa6
#define JVM_INS_IF_ICMPEQ       0x9f
#define JVM_INS_IF_ICMPGE       0xa2
#define JVM_INS_IF_ICMPGT       0xa3
#define JVM_INS_IF_ICMPLE       0xa4
#define JVM_INS_IF_ICMPLT       0xa1
#define JVM_INS_IF_ICMPNE       0xa0
#define JVM_INS_IFEQ            0x99
#define JVM_INS_IFGE            0x9c
#define JVM_INS_IFGT            0x9d
#define JVM_INS_IFLE            0x9e
#define JVM_INS_IFLT            0x9b
#define JVM_INS_IFNE            0x9a
#define JVM_INS_IFNONNULL       0xc7
#define JVM_INS_IFNULL          0xc6
#define JVM_INS_IINC            0x84
#define JVM_INS_ILOAD           0x15
#define JVM_INS_ILOAD_0         0x1a
#define JVM_INS_ILOAD_1         0x1b
#define JVM_INS_ILOAD_2         0x1c
#define JVM_INS_ILOAD_3         0x1d
#define JVM_INS_IMPDEP1         0xfe
#define JVM_INS_IMPDEP2         0xff
#define JVM_INS_IMUL            0x68
#define JVM_INS_INEG            0x74
#define JVM_INS_INSTANCEOF      0xc1
#define JVM_INS_INVOKEDYNAMIC   0xba
#define JVM_INS_INVOKEINTERFACE 0xb9
#define JVM_INS_INVOKESPECIAL   0xb7
#define JVM_INS_INVOKESTATIC    0xb8
#define JVM_INS_INVOKEVIRTUAL   0xb6
#define JVM_INS_IOR             0x80
#define JVM_INS_IREM            0x70
#define JVM_INS_IRETURN         0xac
#define JVM_INS_ISHL            0x78
#define JVM_INS_ISHR            0x7a
#define JVM_INS_ISTORE          0x36
#define JVM_INS_ISTORE_0        0x3b
#define JVM_INS_ISTORE_1        0x3c
#define JVM_INS_ISTORE_2        0x3d
#define JVM_INS_ISTORE_3        0x3e
#define JVM_INS_ISUB            0x64
#define JVM_INS_IUSHR           0x7c
#define JVM_INS_IXOR            0x82
#define JVM_INS_JSR             0xa8
#define JVM_INS_JSR_W           0xc9
#define JVM_INS_L2D             0x8a
#define JVM_INS_L2F             0x89
#define JVM_INS_L2I             0x88
#define JVM_INS_LADD            0x61
#define JVM_INS_LALOAD          0x2f
#define JVM_INS_LAND            0x7f
#define JVM_INS_LASTORE         0x50
#define JVM_INS_LCMP            0x94
#define JVM_INS_LCONST_0        0x09
#define JVM_INS_LCONST_1        0x0a
#define JVM_INS_LDC             0x12
#define JVM_INS_LDC_W           0x13
#define JVM_INS_LDC2_W          0x14
#define JVM_INS_LDIV            0x6d
#define JVM_INS_LLOAD           0x16
#define JVM_INS_LLOAD_0         0x1e
#define JVM_INS_LLOAD_1         0x1f
#define JVM_INS_LLOAD_2         0x20
#define JVM_INS_LLOAD_3         0x21
#define JVM_INS_LMUL            0x69
#define JVM_INS_LNEG            0x75
#define JVM_INS_LOOKUPSWITCH    0xab
#define JVM_INS_LOR             0x81
#define JVM_INS_LREM            0x71
#define JVM_INS_LRETURN         0xad
#define JVM_INS_LSHL            0x79
#define JVM_INS_LSHR            0x7b
#define JVM_INS_LSTORE          0x37
#define JVM_INS_LSTORE_0        0x3f
#define JVM_INS_LSTORE_1        0x40
#define JVM_INS_LSTORE_2        0x41
#define JVM_INS_LSTORE_3        0x42
#define JVM_INS_LSUB            0x65
#define JVM_INS_LUSHR           0x7d
#define JVM_INS_LXOR            0x83
#define JVM_INS_MONITORENTER    0xc2
#define JVM_INS_MONITOREXIT     0xc3
#define JVM_INS_MULTIANEWARRAY  0xc5
#define JVM_INS_NEW             0xbb
#define JVM_INS_NEWARRAY        0xbc
#define JVM_INS_NOP             0x00
#define JVM_INS_POP             0x57
#define JVM_INS_POP2            0x58
#define JVM_INS_PUTFIELD        0xb5
#define JVM_INS_PUTSTATIC       0xb3
#define JVM_INS_RET             0xa9
#define JVM_INS_RETURN          0xb1
#define JVM_INS_SALOAD          0x35
#define JVM_INS_SASTORE         0x56
#define JVM_INS_SIPUSH          0x11
#define JVM_INS_SWAP            0x5f
#define JVM_INS_TABLESWITCH     0xaa
#define JVM_INS_WIDE            0xc4
#define JVM_INS_NONAMESTART     0xcb
#define JVM_INS_NONAMEEND       0xfd

class JVMDecompiler {
    private:
        struct Section {
            char *function_traits;
            char *block_traits;
        };
        int type = JVM_DECOMPILER_TYPE_UNSET;
        char * hexdump_traits(char *buffer0, const void *data, int size, int operand_size){
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
        char * traits_nl(char *traits){
            sprintf(traits, "%s\n", traits);
            return traits;
        }
    public:
        struct Section sections[JVM_DECOMPILER_MAX_SECTIONS];
        JVMDecompiler(){
            for (int i = 0; i < JVM_DECOMPILER_MAX_SECTIONS; i++){
                sections[i].function_traits = NULL;
                sections[i].block_traits = NULL;
            }
        }
        bool Setup(int input_type){
            switch(input_type){
                case JVM_DECOMPILER_TYPE_BLCKS:
                    type = JVM_DECOMPILER_TYPE_BLCKS;
                    break;
                case JVM_DECOMPILER_TYPE_FUNCS:
                    type = JVM_DECOMPILER_TYPE_FUNCS;
                    break;
                default:
                    fprintf(stderr, "[x] unsupported JVM decompiler type\n");
                    type = JVM_DECOMPILER_TYPE_UNSET;
                    return false;
            }
            return true;
        }
        void WriteTraits(char *file_path){
            FILE *fd = fopen(file_path, "w");
            for (int i = 0; i < JVM_DECOMPILER_MAX_SECTIONS; i++){
                if (sections[i].function_traits != NULL){
                    fwrite(sections[i].function_traits, sizeof(char), strlen(sections[i].function_traits), fd);
                }
                if (sections[i].block_traits != NULL){
                    fwrite(sections[i].block_traits, sizeof(char), strlen(sections[i].block_traits), fd);
                }
            }
            fclose(fd);
        }
        void PrintTraits(){
            for (int i = 0; i < JVM_DECOMPILER_MAX_SECTIONS; i++){
                if (sections[i].function_traits != NULL){
                    printf("%s", sections[i].function_traits);
                }
                if (sections[i].block_traits != NULL){
                    printf("%s", sections[i].block_traits);
                }
            }
        }
        ~JVMDecompiler(){
            for (int i = 0; i < JVM_DECOMPILER_MAX_SECTIONS; i++){
                if (sections[i].function_traits != NULL){
                    free(sections[i].function_traits);
                }
                if (sections[i].block_traits != NULL){
                    free(sections[i].block_traits);
                }
            }
        }
};

#endif
