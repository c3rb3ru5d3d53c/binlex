#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <LIEF/PE.hpp>
#include "common.h"

#ifndef RAW_H
#define RAW_H

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif

#define RAW_MAX_SECTIONS 256

#ifdef _WIN32
typedef unsigned int uint;
#endif

#ifdef _WIN32
typedef unsigned int uint;
#endif

using namespace std;

namespace binlex{
    class Raw : public Common {
            //int GetFileSize(FILE *fd);
            typedef struct Hash {
                char *sha256;
            } Hash;
            struct Section {
                void *data;
                int size;
                uint offset;
                Hash hashes;
            };
        public:
            struct Section sections[RAW_MAX_SECTIONS];
            BINLEX_EXPORT Raw();
            BINLEX_EXPORT bool ReadFile(char *file_path, int section_index);
            BINLEX_EXPORT ~Raw();
    };
}

#endif
