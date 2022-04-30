//#include <iostream>
#include "file.h"

using namespace binlex;

void File::CalculateFileHashes(char *file_path){
    tlsh = GetFileTLSH(file_path);
    sha256 = GetFileSHA256(file_path);
    // std::cerr << "#############################################################################" << tlsh
    // 	      << ' ' << sha256
    // 	      << std::endl;
}
