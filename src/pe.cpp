#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/PE.hpp>
#include "pe.h"
#include "common.h"

using namespace std;
using namespace binlex;
using namespace LIEF::PE;

PE::PE(){
    for (int i = 0; i < PE_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        sections[i].data = NULL;
    }
}

bool PE::Setup(MACHINE_TYPES input_mode){
    switch(input_mode){
        case MACHINE_TYPES::IMAGE_FILE_MACHINE_I386:
            mode = MACHINE_TYPES::IMAGE_FILE_MACHINE_I386;
            break;
        case MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64:
            mode = MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64;
            break;
        default:
            mode = MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN;
            fprintf(stderr, "[x] unsupported mode.\n");
            return false;
    }
    return true;
}

bool PE::ReadFile(char *file_path){
    binary = Parser::parse(file_path);
    if (mode != binary->header().machine()){
        fprintf(stderr, "[x] incorrect mode for binary architecture\n");
        return false;
    }
    ParseSections();
    return true;
}

bool PE::ReadBuffer(void *data, size_t size){
    vector<uint8_t> data_v((uint8_t *)data, (uint8_t *)data + size);
    binary = Parser::parse(data_v);
    if (mode != binary->header().machine()){
        fprintf(stderr, "[x] incorrect mode for binary architecture\n");
        return false;
    }
    ParseSections();
    return true;
}

void PE::ParseSections(){
    uint index = 0;
    it_sections local_sections = binary->sections();
    for (auto it = local_sections.begin(); it != local_sections.end(); it++){
        if (it->characteristics() & (uint32_t)SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE){
            sections[index].offset = it->offset();
            sections[index].size = it->sizeof_raw_data();
            sections[index].data = malloc(sections[index].size);
            memset(sections[index].data, 0, sections[index].size);
            vector<uint8_t> data = binary->get_content_from_virtual_address(it->virtual_address(), it->sizeof_raw_data());
            memcpy(sections[index].data, &data[0], sections[index].size);
            if (binary->has_exports()){
                Export exports = binary->get_export();
                it_export_entries export_entries = exports.entries();
                for (auto j = export_entries.begin(); j != export_entries.end(); j++){
                    uint64_t tmp_offset = binary->rva_to_offset(j->address());
                    if (tmp_offset > sections[index].offset &&
                        tmp_offset < sections[index].offset + sections[index].size){
                        sections[index].functions.insert(tmp_offset-sections[index].offset);
                    }
                }
            }
        }
        index++;
    }
}

PE::~PE(){
    for (int i = 0; i < PE_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        if (sections[i].data != NULL){
            free(sections[i].data);
        }
        sections[i].functions.clear();
    }
}