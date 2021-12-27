#include <iostream>
#include <memory>
#include <set>
#include <LIEF/PE.hpp>
#include "common.h"

#ifndef PEREV_H
#define PEREV_H

#define PEREV_MAX_SECTIONS 256

using namespace std;
using namespace LIEF::PE;

namespace binlex {
class PEREV : public Common {
    FILE *fd = NULL;
    unique_ptr<const Binary> binary;
    set<uint64_t> function_rvas;
    set<uint64_t> function_offsets;
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
        ~PEREV();
};
};

#endif