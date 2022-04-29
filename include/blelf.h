#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/ELF.hpp>
#include "common.h"

#ifndef ELF_H
#define ELF_H

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
            struct Section {
                uint offset;
                int size;
                void *data;
                set<uint64_t> functions;
            };
            struct Section sections[ELF_MAX_SECTIONS];
            ELF();
            bool Setup(ARCH input_mode);
            bool ReadFile(char *file_path);
            bool ReadBuffer(void *data, size_t size);
            ~ELF();
    };
};

#endif