#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>
#include <math.h>
#include <capstone/capstone.h>
#include "decompiler_rev.h"

using namespace std;
using namespace binlex;

// WIP

DecompilerREV::DecompilerREV(){
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].pc = 0;
        sections[i].traits = NULL;
        sections[i].traits_count = 0;

    }
}

bool DecompilerREV::AllocTraits(uint count, uint index){
    sections[index].traits_count = sections[index].traits_count + count;
    if (realloc(sections[index].traits, sizeof(traits_t) * sections[index].traits_count) == NULL){
        return false;
    }
    return true;
}

bool DecompilerREV::Setup(cs_arch arch, cs_mode mode, uint index){
    sections[index].status = cs_open(arch, mode, &sections[index].handle);
    if (sections[index].status != CS_ERR_OK){
        return false;
    }
    sections[index].status = cs_option(sections[index].handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (sections[index].status != CS_ERR_OK){
        return false;
    }
    return true;
}

// void DecompilerREV::Seek(uint offset, uint index){
//     sections[index].pc = offset;
//     sections[index].code_size = sections[index].data_size - offset;
//     memmove(sections[index].data, sections[index].code + sections[index].pc, sections[index].code_size);
//     sections[index].code = (uint8_t *)sections[index].data;
// }

uint DecompilerREV::Decompile(void *data, size_t data_size, size_t data_offset, uint index){
    sections[index].pc = 0;
    sections[index].data = data;
    sections[index].data_size = data_size;
    const uint8_t *code = (uint8_t *)data;
    cs_insn *insn = cs_malloc(sections[index].handle);
    while (true){
        bool result = cs_disasm_iter(sections[index].handle, &code, &sections[index].data_size, &sections[index].pc, insn);
        if (sections[index].pc >= data_size){
            break;
        }
        printf("pc: %ld, %ld\n", sections[index].pc, sections[index].data_size);
    }
    cs_free(insn, 1);
    return sections[index].pc;
}

DecompilerREV::~DecompilerREV(){
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++){
        if (sections[i].traits != NULL){
            free(sections[i].traits);
            sections[i].traits_count = 0;
        }
    }
}
