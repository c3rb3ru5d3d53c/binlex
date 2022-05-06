#include "blelf.h"

using namespace binlex;
using namespace LIEF::ELF;

ELF::ELF(){
    total_exec_sections = 0;

    for (int i = 0; i < BINARY_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        sections[i].data = NULL;
    }
}

bool ELF::Setup(ARCH input_mode){
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

bool ELF::ReadVector(const std::vector<uint8_t> &data){
    CalculateFileHashes(data);
    binary = Parser::parse(data);
    if (binary == NULL){
        return false;
    }
    if (mode != binary->header().machine_type()){
        fprintf(stderr, "[x] incorrect mode for binary architecture\n");
        return false;
    }
    return ParseSections();
}

bool ELF::ParseSections(){
    uint index = 0;
    it_sections local_sections = binary->sections();
    for (auto it = local_sections.begin(); it != local_sections.end(); it++){
        if (it->flags() & (uint64_t)ELF_SECTION_FLAGS::SHF_EXECINSTR){
            sections[index].offset = it->offset();
            sections[index].size = it->original_size();
            sections[index].data = malloc(sections[index].size);
            memset(sections[index].data, 0, sections[index].size);
            vector<uint8_t> data = binary->get_content_from_virtual_address(it->virtual_address(), it->original_size());
            memcpy(sections[index].data, &data[0], sections[index].size);
            it_exported_symbols symbols = binary->exported_symbols();
            // Add export to function list
            for (auto j = symbols.begin(); j != symbols.end(); j++){
                uint64_t tmp_offset = binary->virtual_address_to_offset(j->value());
                PRINT_DEBUG("Elf Export offset: 0x%x\n", (int)tmp_offset);
                if (tmp_offset > sections[index].offset &&
                    tmp_offset < sections[index].offset + sections[index].size){
                    sections[index].functions.insert(tmp_offset-sections[index].offset);
                }
            }
            // Add entrypoint to the function list
            uint64_t entrypoint_offset = binary->virtual_address_to_offset(binary->entrypoint());
            PRINT_DEBUG("Elf Entrypoint offset: 0x%x\n", (int)entrypoint_offset);
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

ELF::~ELF(){
    for (int i = 0; i < total_exec_sections; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        free(sections[i].data);
        sections[i].functions.clear();
    }
}
