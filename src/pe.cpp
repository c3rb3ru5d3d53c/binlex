#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include "pe.h"
#include "common.h"
#include <iostream>
#include <LIEF/PE.hpp>
#include <cassert>

using namespace std;
using namespace binlex;
using namespace LIEF::PE;

PE::PE(){
    total_exec_sections = 0;

    for (int i = 0; i < BINARY_MAX_SECTIONS; i++){
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
    if (FileExists(file_path) == false){
        return false;
    }
    CalculateFileHashes(file_path);
    assert(!tlsh.empty());
    assert(!sha256.empty());
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

bool PE::IsDotNet(){
    return binary->has(DATA_DIRECTORY::CLR_RUNTIME_HEADER);
}

bool PE::ParseSections(){
    uint32_t index = 0;
    it_sections local_sections = binary->sections();
    for (auto it = local_sections.begin(); it != local_sections.end(); it++){
        if (it->characteristics() & (uint32_t)SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE){
            sections[index].offset = it->offset();
            sections[index].size = it->sizeof_raw_data();
            sections[index].data = malloc(sections[index].size);
            memset(sections[index].data, 0, sections[index].size);
            vector<uint8_t> data = binary->get_content_from_virtual_address(it->virtual_address(), it->sizeof_raw_data());
            memcpy(sections[index].data, &data[0], sections[index].size);
            // Add exports to the function list
            if (binary->has_exports()){
                Export exports = binary->get_export();
                it_export_entries export_entries = exports.entries();
                for (auto j = export_entries.begin(); j != export_entries.end(); j++){
                    PRINT_DEBUG("PE Export offset: 0x%x\n", binary->rva_to_offset(j->address()));
                    uint64_t tmp_offset = binary->rva_to_offset(j->address());
                    if (tmp_offset > sections[index].offset &&
                        tmp_offset < sections[index].offset + sections[index].size){
                        sections[index].functions.insert(tmp_offset-sections[index].offset);
                    }
                }
            }
            // Add entrypoint to the function list
            uint64_t entrypoint_offset = binary->va_to_offset(binary->entrypoint());
            PRINT_DEBUG("PE Entrypoint offset: 0x%x\n", entrypoint_offset);
            if (entrypoint_offset > sections[index].offset && entrypoint_offset < sections[index].offset + sections[index].size){
                sections[index].functions.insert(entrypoint_offset-sections[index].offset);
            }
            index++;
            if (BINARY_MAX_SECTIONS == index)
            {
                fprintf(stderr, "[x] malformed binary, too many executable sections\n");
                return false;
            }
        }
    }

    total_exec_sections = index + 1;
    return true;
}

PE::~PE(){
    for (int i = 0; i < total_exec_sections; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        free(sections[i].data);
        sections[i].functions.clear();
    }
}
