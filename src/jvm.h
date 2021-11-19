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

#endif
