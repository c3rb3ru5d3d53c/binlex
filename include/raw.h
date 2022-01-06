#include <stdio.h>
#include <stdlib.h>

#ifndef RAW_H
#define RAW_H

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINELEX_EXPORT 
#endif

#define RAW_MAX_SECTIONS 256

#ifdef _WIN32
typedef unsigned int uint;
#endif

#ifdef _WIN32
typedef unsigned int uint;
#endif

namespace binlex{
    class Raw{
            int GetFileSize(FILE *fd);
            struct Section {
                void *data;
                int size;
                uint offset;
            };
        public:
            struct Section sections[RAW_MAX_SECTIONS];
            BINLEX_EXPORT Raw();
            BINLEX_EXPORT bool ReadFile(char *file_path, int section_index);
            BINLEX_EXPORT ~Raw();
    };
}

#endif
