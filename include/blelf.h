#ifndef ELF_H
#define ELF_H

#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/ELF.hpp>
#include "common.h"

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT 
#endif

using namespace std;
using namespace LIEF::ELF;

namespace binlex{
    class ELF : public Common{
        private:
            bool ParseSections();
        public:
            ARCH mode = ARCH::EM_NONE;
            unique_ptr<LIEF::ELF::Binary> binary;
            struct Section {
                uint offset;
                int size;
                void *data;
                set<uint64_t> functions;
            };
            struct Section sections[BINARY_MAX_SECTIONS];
            uint32_t total_exec_sections;

            BINLEX_EXPORT ELF();
            BINLEX_EXPORT bool Setup(ARCH input_mode);
            BINLEX_EXPORT bool ReadFile(char *file_path);
            BINLEX_EXPORT bool ReadBuffer(void *data, size_t size);
            BINLEX_EXPORT ~ELF();
    };
};

#endif
