#include "raw.h"

using namespace binlex;

Raw::Raw(){
    for (int i = 0; i < BINARY_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        sections[i].data = NULL;
    }
}

int Raw::GetFileSize(FILE *fd){
    int start = ftell(fd);
    fseek(fd, 0, SEEK_END);
    int size = ftell(fd);
    fseek(fd, start, SEEK_SET);
    return size;
}

bool Raw::ReadVector(const std::vector<uint8_t> &data){
    if (binary_arch == BINARY_ARCH_UNKNOWN ||
        binary_mode == BINARY_MODE_UNKNOWN){
        return false;
    } else {
        if (binary_arch == BINARY_ARCH_X86 &&
            binary_mode == BINARY_MODE_32){
            g_args.options.mode = "raw:x86";
        } else if ((binary_arch == BINARY_ARCH_X86 ||
            binary_arch == BINARY_ARCH_X86_64) &&
            binary_mode == BINARY_MODE_64){
                g_args.options.mode = "raw:x86_64";
            }
    }
    binary_type = BINARY_TYPE_RAW;
    const int section_index = 0; // The parameter was always zero.
    CalculateFileHashes(data);
    // The original ftell was always called after opening the file, hence 0.
    sections[section_index].offset = 0;
    sections[section_index].functions.insert(0);
    sections[section_index].size = data.size();
    sections[section_index].data = malloc(data.size());
    total_exec_sections++;
    if(sections[section_index].data == NULL) {
	    return false;
    }
    std::copy(data.begin(), data.end(), static_cast<uint8_t*>(sections[section_index].data));
    return true;
}

Raw::~Raw(){
    for (int i = 0; i < BINARY_MAX_SECTIONS; i++){
        if (sections[i].data != NULL){
            free(sections[i].data);
            sections[i].size = 0;
            sections[i].offset = 0;
        }
    }
}
