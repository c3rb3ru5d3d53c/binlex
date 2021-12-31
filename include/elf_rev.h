#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/ELF.hpp>

#ifndef ELFREV_H
#define ELFREV_H

using namespace std;
using namespace LIEF::ELF;

namespace binlex{
    class ELFREV{
        public:
            ARCH mode = ARCH::EM_NONE;
            unique_ptr<LIEF::ELF::Binary> binary;
            struct Section {
                uint offset;
                int size;
                void *data;
                set<uint64_t> functions;
            };
            void ParseSections();
            bool Setup(ARCH input_mode);
            bool ReadFile(char *file_path);
            bool ReadBuffer(void *data, size_t size);
    };
};

#endif