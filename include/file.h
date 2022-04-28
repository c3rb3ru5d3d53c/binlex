#include <iostream>
#include <memory>
#include <set>

#ifndef FILE_H
#define FILE_H

using namespace std;

namespace binlex {
    class File {
        public:
            string sha256;
            string tlsh;
            struct Section {
                uint offset;
                int size;
                void *data;
                set<uint64_t> functions;
            };
    };
};

#endif
