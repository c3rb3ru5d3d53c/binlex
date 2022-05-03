#include "raw.h"
#include <stdexcept>

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
    try {
	std::vector<uint8_t> data_v(ReadFileIntoVector(file_path));
	ReadVector(data_v);
    }
    catch(const std::exception &err) {
	cerr << "error while reading: " << err.what() << endl;
	return false;
    }
    return true;
}

bool Raw::ReadBuffer(void *data, size_t size){
    vector<uint8_t> data_v((uint8_t *)data, (uint8_t *)data + size);
    return ReadVector(data_v);
}

bool Raw::ReadVector(const std::vector<uint8_t> &data){
    const int section_index = 0; // The parameter was always zero.
    CalculateFileHashes(data);
    // The original ftell was always called after opening the file, hence 0.
    sections[section_index].offset = 0;
    sections[section_index].size = data.size();
    sections[section_index].data = malloc(data.size());
    if(sections[section_index].data == NULL) {
	// No more memory.
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
