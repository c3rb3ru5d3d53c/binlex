#include "file.h"

using namespace binlex;

void File::CalculateFileHashes(char *file_path){
    tlsh = GetFileTLSH(file_path);
    sha256 = GetFileSHA256(file_path);
}

bool File::FileExists(char *file_path){
    if (access(file_path, F_OK ) == 0){
        return true;
    }
    return false;
}
