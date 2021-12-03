#include <vector>
#include <capstone/capstone.h>
#include "common.h"

#ifndef DECOMPILER_REV_H
#define DECOMPILER_REV_H

#define DECOMPILER_REV_MAX_SECTIONS 256

using namespace std;

namespace binlex {
    class DecompilerREV{
        private:
            struct traits_t {
                string type;
                string bytes;
                string trait;
                uint edges;
                uint blocks;
                uint insns;
            };
        public:
            struct Section {
                csh handle;
                cs_err status;
                uint offset;
                uint64_t pc;
                traits_t *traits;
                uint traits_count;
                size_t data_size;
                void *data;
                vector<uint64_t> blocks;
                vector<uint64_t> functions;
                vector<uint64_t> visited;
            };
            struct Section sections[DECOMPILER_REV_MAX_SECTIONS];
            Common common;
            DecompilerREV();
            /**
            Set up Capstone Decompiler Architecure and Mode
            @param arch Capstone Decompiler Architecure
            @param cs_mode Capstone Mode
            @param index section index
            */
            bool Setup(cs_arch arch, cs_mode mode, uint index);
            uint Decompile(void *data, size_t data_size, size_t data_offset, uint index);
            /**
            Allocate Additional Traits
            @param count number of additional traits to allocate
            @param index the section index
            @return bool
            */
            bool AllocTraits(uint count, uint index);
            //void Seek(uint offset, uint index);
            ~DecompilerREV();

    };
}
#endif
