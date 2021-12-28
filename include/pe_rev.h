#include <iostream>
#include <memory>
#include <set>
#include <LIEF/PE.hpp>
#include "common.h"

#ifndef PEREV_H
#define PEREV_H

#define PEREV_MAX_SECTIONS 256
#define PEREV_MODE_X86     0
#define PEREV_MODE_X86_64  1
#define PEREV_MODE_UNSET   2

using namespace std;
using namespace LIEF::PE;

namespace binlex {
    class PEREV : public Common {
        MACHINE_TYPES mode = MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN;
        FILE *fd = NULL;
        unique_ptr<Binary> binary;
        struct Section {
            uint offset;
            int size;
            void *data;
            set<uint64_t> functions;
        };
        public:
            PEREV();
            struct Section sections[PEREV_MAX_SECTIONS];
            bool ReadFile(char *file_path);
            bool Setup(MACHINE_TYPES input_mode);
            ~PEREV();
    };
};

#endif