#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/ELF.hpp>
#include "elf_rev.h"

using namespace std;
using namespace binlex;
using namespace LIEF::ELF;

bool ELFREV::Setup(ARCH input_mode){
    switch(input_mode){
        case ARCH::EM_386:
            mode = ARCH::EM_386;
            break;
        case ARCH::EM_X86_64:
            mode = ARCH::EM_X86_64;
            break;
        default:
            mode = ARCH::EM_NONE;
            fprintf(stderr, "[x] unsupported mode.\n");
            return false;
    }
    return true;
}

bool ELFREV::ReadFile(char *file_path){
    binary = Parser::parse(file_path);
    if (mode != binary->header().machine_type()){
        fprintf(stderr, "[x] incorrect mode for binary architecture\n");
        return false;
    }
    ParseSections();
    return true;
}

bool ELFREV::ReadBuffer(void *data, size_t size){
    vector<uint8_t> data_v((uint8_t *)data, (uint8_t *)data + size);
    binary = Parser::parse(data_v);
    if (mode != binary->header().machine_type()){
        fprintf(stderr, "[x] incorrect mode for binary architecture\n");
        return false;
    }
    ParseSections();
    return true;
}

void ELFREV::ParseSections(){
    uint index = 0;
    it_sections local_sections = binary->sections();
    for (auto it = local_sections.begin(); it != local_sections.end(); it++){

    }
}