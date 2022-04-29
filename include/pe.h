#ifndef PE_H
#define PE_H

#ifdef _WIN32
#include <Windows.h>
#include <stdexcept>
#endif
#include <iostream>
#include <memory>
#include <set>
#include <LIEF/PE.hpp>
#include "common.h"


#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT 
#endif

using namespace std;
using namespace LIEF::PE;

namespace binlex {
    class PE {
        private:
            bool ParseSections();
        public: 
        #ifndef _WIN32
            MACHINE_TYPES mode = MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN;
        #else
            MACHINE_TYPES mode = MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN;
        #endif
            unique_ptr<LIEF::PE::Binary> binary;
            struct Section {
                uint offset;
                int size;
                void *data;
                set<uint64_t> functions;
            };
            BINLEX_EXPORT PE();
            struct Section sections[BINARY_MAX_SECTIONS];
            uint32_t total_exec_sections;

            /**
            @param file_path path to the executable
            @return bool
            */
            BINLEX_EXPORT bool ReadFile(char *file_path);
            /**
            @param data pointer to executable in memory
            @param size size of the data
            @return bool
            */
            BINLEX_EXPORT bool ReadBuffer(void *data, size_t size);
            /**
            Setup to Read Specific PE Format
            @param input_mode MACHINE_TYPES::IMAGE_FILE_MACHINE_<arch>
            @return bool
            */
            BINLEX_EXPORT bool Setup(MACHINE_TYPES input_mode);
            BINLEX_EXPORT ~PE();
    };
};

#endif
