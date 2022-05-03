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

bool Raw::ReadFile(const char *file_path){
    const int section_index = 0;
    FILE *fd = fopen(file_path, "rb");
    if(!fd) {
      return false;
    }
    sections[section_index].offset = ftell(fd);
    sections[section_index].size = GetFileSize(fd);
    sections[section_index].data = malloc(sections[section_index].size);
    memset(sections[section_index].data, 0, sections[section_index].size);
    fread(sections[section_index].data, sections[section_index].size, 1, fd);
    fclose(fd);
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
