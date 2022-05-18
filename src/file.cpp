#include "file.h"

using namespace binlex;

void File::CalculateFileHashes(char *file_path){
    tlsh = GetFileTLSH(file_path);
    sha256 = GetFileSHA256(file_path);
}

void File::CalculateFileHashes(const vector<uint8_t> &data){
    tlsh = GetTLSH(&data[0], data.size());
    sha256 = GetSHA256(&data[0], data.size());
}

bool File::SetArchitecture(int arch, int mode){
    switch(binary_arch){
        case BINARY_ARCH_X86:
        case BINARY_ARCH_X86_64:
            binary_arch = arch;
            break;
        default:
            binary_arch = BINARY_ARCH_UNKNOWN;
            return false;
    }
    switch(mode){
        case BINARY_MODE_32:
        case BINARY_MODE_64:
        case BINARY_MODE_CIL:
            binary_mode = mode;
            break;
        default:
            binary_mode = BINARY_MODE_UNKNOWN;
            return false;
    }
    return true;
}

std::vector<uint8_t> File::ReadFileIntoVector(const char *file_path){
    FILE *inp;
    uint8_t buf[8192];
    size_t bread;
    std::vector<uint8_t> data;

    inp = fopen(file_path, "rb");
    if(!inp){
	    throw std::runtime_error(strerror(errno));
    }
    while((bread = fread(buf, 1, sizeof(buf), inp)) > 0){
	    data.insert(data.end(), buf, buf + bread);
    }
    if(errno != 0) {
	    throw std::runtime_error(strerror(errno));
    }
    fclose(inp);
    return data;
}

bool File::ReadFile(const char *file_path){
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

bool File::ReadBuffer(void *data, size_t size){
    vector<uint8_t> data_v((uint8_t *)data, (uint8_t *)data + size);
    return ReadVector(data_v);
}
