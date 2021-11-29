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
#include "json.h"
#include "decompiler_rev.h"

using namespace std;
using json = nlohmann::json;
using namespace binlex;

DecompilerREV::DecompilerREV(){
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++){
        sections[i].pc = 0;
        sections[i].code_size = 0;
        sections[i].data_size = 0;
        sections[i].data_offset = 0;
        sections[i].data = NULL;
        sections[i].code = NULL;
        sections[i].b_edges = 0;
        sections[i].f_edges = 0;
        sections[i].b_end = false;
        sections[i].f_end = false;
        sections[i].b_count = 0;
        sections[i].b_insn_count = 0;
        sections[i].f_insn_count = 0;
        sections[i].b_trait.clear();
        sections[i].f_trait.clear();
        sections[i].f_bytes.clear();
        sections[i].b_bytes.clear();
        sections[i].blocks.clear();
        sections[i].functions.clear();
        sections[i].visited.clear();
    }
}

json DecompilerREV::GetTraits(){
    json result;
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++){
        if (sections[i].traits.is_null() == false){
            if (sections[i].traits.is_null() == false){
                for (int j = 0; j < sections[i].traits.size(); j++){
                    result.push_back(sections[i].traits[j]);
                }
            }
        }
    }
    return result;
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

void DecompilerREV::ClearBlock(uint index){
    sections[index].b_trait.clear();
    sections[index].b_bytes.clear();
    sections[index].b_edges = 0;
    sections[index].b_insn_count = 0;
    sections[index].b_end = false;
}

void DecompilerREV::ClearTrait(uint index){
    sections[index].f_trait.clear();
    sections[index].f_bytes.clear();
    sections[index].f_edges = 0;
    sections[index].f_insn_count = 0;
    sections[index].f_end = false;
}

void DecompilerREV::AddEdges(uint count, uint index){
    sections[index].b_edges = sections[index].b_edges + count;
    sections[index].f_edges = sections[index].f_edges + count;
}

void DecompilerREV::CollectBlockTrait(uint index){
    json trait;
    trait["type"] = "block";
    trait["trait"] = common.TrimRight(sections[index].b_trait);
    trait["edges"] = sections[index].b_edges;
    trait["bytes"] = common.TrimRight(sections[index].b_bytes);
    trait["size"] = common.GetByteSize(sections[index].b_bytes);
    trait["instructions"] = sections[index].b_insn_count;
    sections[index].traits.push_back(trait);
    ClearBlock(index);
}

void DecompilerREV::CollectFunctionTrait(uint index){
    json trait;
    trait["type"] = "function";
    trait["trait"] = common.TrimRight(sections[index].f_trait);
    trait["edges"] = sections[index].f_edges;
    trait["bytes"] = common.TrimRight(sections[index].f_bytes);
    trait["size"] = common.GetByteSize(sections[index].f_bytes);
    trait["instructions"] = sections[index].f_insn_count;
    sections[index].traits.push_back(trait);
    ClearTrait(index);
}

void DecompilerREV::PrintTraits(bool pretty){
    json traits = GetTraits();
    if (pretty == false){
        cout << traits.dump() << endl;
    } else {
        cout << traits.dump(4) << endl;
    }
}

void DecompilerREV::WriteTraits(char *file_path, bool pretty){
    FILE *fd = fopen(file_path, "w");
    string traits;
    if (pretty == false){
        traits = GetTraits().dump();
    } else {
        traits = GetTraits().dump(4);
    }
    if (traits.length() > 0){
        traits = traits + '\n';
    }
    fwrite(traits.c_str(), sizeof(char), traits.length(), fd);
    fclose(fd);
}

void DecompilerREV::Seek(uint offset, uint index){
    sections[index].pc = offset;
    sections[index].code_size = sections[index].data_size - offset;
    memmove(sections[index].data, sections[index].code + sections[index].pc, sections[index].code_size);
    sections[index].code = (uint8_t *)sections[index].data;
}

uint DecompilerREV::Decompile(void *data, size_t data_size, size_t data_offset, uint index){
    sections[index].pc = 0;
    sections[index].data = data;
    sections[index].data_size = data_size;
    sections[index].data_offset = data_offset;
    sections[index].code = (uint8_t *)data;
    cs_insn *insn = cs_malloc(sections[index].handle);
    while (true){
        bool result = cs_disasm_iter(sections[index].handle, &sections[index].code, &sections[index].code_size, &sections[index].pc, insn);
        if (sections[index].pc >= data_size){
            break;
        }
        if (result == false){
            Seek(sections[index].pc + 1, index);
            continue;
        }
        printf("pc: %ld, %ld\n", sections[index].pc, sections[index].data_size);
    }
    cs_free(insn, 1);
    return sections[index].pc;
    }

DecompilerREV::~DecompilerREV(){
    for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++){
        cs_close(&sections[i].handle);
    }
}
