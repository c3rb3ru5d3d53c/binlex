#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/PE.hpp>
#include "pe_rev.h"
#include "common.h"

using namespace std;
using namespace binlex;
using namespace LIEF::PE;

PEREV::PEREV(){
    for (int i = 0; i < PEREV_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        sections[i].data = NULL;
    }
}

bool PEREV::Setup(MACHINE_TYPES input_mode){
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

bool PEREV::ReadFile(char *file_path){
    fd = fopen(file_path, "rb");
    if (fd == NULL){
		fprintf(stderr, "[x] failed to open %s\n", file_path);
		return false;
	}
    binary = Parser::parse(file_path);
    if (mode != binary->header().machine()){
        fprintf(stderr, "[x] incorrect mode for binary architecture\n");
        return false;
    }
    uint index = 0;
    it_sections local_sections = binary->sections();
    for (auto it = local_sections.begin(); it != local_sections.end(); it++){
        if (it->characteristics() & 0x20000000){
            sections[index].offset = it->offset();
            sections[index].size = it->sizeof_raw_data();
            sections[index].data = malloc(sections[index].size);
            memset(sections[index].data, 0, sections[index].size);
            fseek(fd, sections[index].offset, SEEK_SET);
            fread(sections[index].data, sections[index].size, 1, fd);
            if (binary->has_exports()){
                Export exports = binary->get_export();
                it_export_entries export_entries = exports.entries();
                for (auto j = export_entries.begin(); j != export_entries.end(); j++){
                    uint64_t tmp_offset = binary->rva_to_offset(j->address());
                    if (tmp_offset > sections[index].offset &&
                        tmp_offset < sections[index].offset + sections[index].size){
                        // Need to validate these are correct
                        sections[index].functions.insert(tmp_offset-sections[index].offset);
                    }
                }
            }
        }
        index++;
    }
    return true;
}

PEREV::~PEREV(){
    if (fd != NULL){
        fclose(fd);
    }
    for (int i = 0; i < PEREV_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        if (sections[i].data != NULL){
            free(sections[i].data);
        }
    }
}