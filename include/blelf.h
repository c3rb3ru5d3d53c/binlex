#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/ELF.hpp>
#include "common.h"

#ifndef ELF_H
#define ELF_H

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif
#define ELF_MAX_SECTIONS 256

using namespace std;
using namespace LIEF::ELF;

namespace binlex{
    class ELF : public Common{
        private:
            void ParseSections();
        public:
            ARCH mode = ARCH::EM_NONE;
            unique_ptr<LIEF::ELF::Binary> binary;
            struct Hash {
                char *sha256;
            };
            struct Section {
                uint offset;
                int size;
                void *data;
                set<uint64_t> functions;

            };
            struct Hash hashes;
            struct Section sections[ELF_MAX_SECTIONS];
            BINLEX_EXPORT ELF();
            BINLEX_EXPORT bool Setup(ARCH input_mode);
            BINLEX_EXPORT bool ReadFile(char *file_path);
            BINLEX_EXPORT bool ReadBuffer(void *data, size_t size);
            BINLEX_EXPORT ~ELF();
    };
};

#endif