#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <capstone/capstone.h>

#ifndef DECOMPILER_H
#define DECOMPILER_H

#define DECOMPILER_TYPE_FUNCS 0
#define DECOMPILER_TYPE_BLCKS 1

class Decompiler{
    private:
        csh cs_handle;
        char *temp = NULL;
        char * hexdump_le(const void *data, int size){
            int buffer_size = size * 2 + size;
            char *buffer0 = (char *)malloc(buffer_size);
            memset((void *)buffer0, 0, buffer_size);
            const unsigned char * pc = (const unsigned char *)data;
            int count = 0;
            for (int i = size - 1; i >= 0; i--){
                if (count == 0){
                    sprintf(buffer0, "%s%02x", buffer0, pc[i]);
                } else {
                    sprintf(buffer0, "%s %02x", buffer0, pc[i]);
                }
                count++;
            }
            return buffer0;
        }
        char * hexdump_be(const void *data, int size){
            int buffer_size = size * 2 + size;
            char *buffer0 = (char *)malloc(buffer_size);
            memset((void *)buffer0, 0, buffer_size);
            const unsigned char * pc = (const unsigned char *)data;
            int count = 0;
            for (int i = 0; i < size; i++){
                if (count == 0){
                    sprintf(buffer0, "%s%02x", buffer0, pc[i]);
                } else {
                    sprintf(buffer0, "%s %02x", buffer0, pc[i]);
                }
                count++;
            }
            return buffer0;
        }
        char * wildcard_bytes(char *str, char *wild){
            char wildcard[] = "??";
            char *offset = strstr(str, wild);
            if (offset != 0){
                for (int i = 0; i < strlen(wild);){
                    memcpy(offset + i, &wildcard, 2);
                    i = i + 3;
                }
            }
            return offset;
        }
        void wildcard_null(char *bytes){
            char wildcard[] = "??";
            char *buffer0 = (char *)malloc(3);
            memset(buffer0, 0, 3);
            for (int i = strlen(bytes) + 1; i >= 0;){
                i = i - 3;
                if (i < 0){
                    break;
                }
                memcpy(buffer0, bytes + i, 2);
                if (strcmp(buffer0, (char *)"00") == 0){
                    memcpy(bytes + i, &wildcard, 2);
                } else {
                    break;
                }
            }
            free(buffer0);
        }
        char * hexdump_mem_disp(long int disp){
            int size = sizeof(disp) * 2 + sizeof(disp);
            char *buffer0 = (char *)malloc(size);
            memset((void *)buffer0, 0, size);
            const unsigned char * pc = (const unsigned char *)&disp;
            int count = 0;
            for (int i = 0; i < sizeof(disp) -1 ; i++){
                if (pc[i] != 0 && pc[i] != 255){
                    if (count == 0){
                        sprintf(buffer0, "%s%02x", buffer0, pc[i]);
                    } else {
                        sprintf(buffer0, "%s %02x", buffer0, pc[i]);
                    }
                    count++;
                }
            }
            return buffer0;
        }
    public:
        char *traits = NULL;
        int decompiler_type = DECOMPILE_MODE_FUNCS;
        void Setup(cs_arch arch, cs_mode mode){
            assert(cs_open(arch, mode, &cs_handle) == CS_ERR_OK);
            cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_option(cs_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        }
        void FreeTraits(){
            if (traits != NULL){
                free(traits);
            }
        }
        int write_traits(char *output){
            FILE *fd = fopen(output, "w");
            if (fd == NULL){
                fprintf(stderr, "failed to open file %s\n", output);
            }
            int result = fwrite(traits, sizeof(char), strlen(traits), fd);
            if (result <= 0){
                fprintf(stderr, "failed to write file %s\n", output);
            }
            fclose(fd);
            return result;
        }
        void x86_64(void *data, int data_size){
            cs_insn *insn;
            char *disp = NULL;
            char *bytes = NULL;
            size_t count;
            temp = (char *)malloc(data_size * 2 + data_size + 1);
            memset((void *)temp, 0, data_size * 2 + data_size);
            count = cs_disasm(cs_handle, (const uint8_t *)data, data_size, 0x0, 0, &insn);
            if (count > 0) {
                size_t j;
                for (j = 0; j < count; j++) {
                    bytes = hexdump_be(insn[j].bytes, insn[j].size);
                    for (int k = 0; k < insn[j].detail->x86.op_count; k++) {
                        cs_x86_op *op = &(insn[j].detail->x86.operands[k]);
                        switch((int)op->type) {
                            case X86_OP_MEM:
                                if (op->mem.disp != 0)
                                    disp = hexdump_mem_disp(op->mem.disp);
                                    wildcard_bytes(bytes, disp);
                                break;
                            default:
                                break;
                        }
                    }
                    wildcard_null(bytes);
                    if (decompiler_type == DECOMPILER_TYPE_FUNCS &&
                        insn[j].id == X86_INS_RET){
                        sprintf(temp + strlen(temp), "%s\n", bytes);
                        //printf("%s\n", bytes);
                    } else if (decompiler_type == DECOMPILER_TYPE_BLCKS &&
                        (insn[j].id == X86_INS_JMP ||
                            insn[j].id == X86_INS_JNE ||
                            insn[j].id == X86_INS_JNO ||
                            insn[j].id == X86_INS_JNP ||
                            insn[j].id == X86_INS_JL ||
                            insn[j].id == X86_INS_JLE ||
                            insn[j].id == X86_INS_JG ||
                            insn[j].id == X86_INS_JGE ||
                            insn[j].id == X86_INS_JE ||
                            insn[j].id == X86_INS_JECXZ ||
                            insn[j].id == X86_INS_JCXZ ||
                            insn[j].id == X86_INS_JB ||
                            insn[j].id == X86_INS_JBE ||
                            insn[j].id == X86_INS_JA ||
                            insn[j].id == X86_INS_JAE ||
                            insn[j].id == X86_INS_JNS ||
                            insn[j].id == X86_INS_JO ||
                            insn[j].id == X86_INS_JP ||
                            insn[j].id == X86_INS_JRCXZ ||
                            insn[j].id == X86_INS_JS)){
                        sprintf(temp + strlen(temp), "%s\n", bytes);
                        //printf("%s\n", bytes);
                    } else {
                        if (j + 1 >= count){
                            sprintf(temp + strlen(temp), "%s\n", bytes);
                            //printf("%s\n", bytes);
                        } else {
                            sprintf(temp + strlen(temp), "%s ", bytes);
                            //printf("%s ", bytes);
                        }
                    }
                    free(bytes);
                }
                cs_free(insn, count);
            }
            if (traits == NULL){
                traits = (char *)malloc(strlen(temp)+1);
                sprintf(traits, "%s", temp);
            } else {
                traits = (char *)realloc(traits, strlen(traits) + strlen(temp) + 1);
                sprintf(traits, "%s", temp);
            }
            free(temp);
        }
        ~Decompiler(){
            cs_close(&cs_handle);
            FreeTraits();
        }
};

#endif
