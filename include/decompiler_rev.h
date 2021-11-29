#include <vector>
#include <capstone/capstone.h>
#include "common.h"

#ifndef DECOMPILER_REV_H
#define DECOMPILER_REV_H

#define DECOMPILER_REV_MAX_SECTIONS 256

using namespace std;
using json = nlohmann::json;

namespace binlex {
    class DecompilerREV{
        private:
            json GetTraits();
        public:
            struct Section {
                csh handle;
                cs_err status;
                json traits;
                uint offset;
                uint64_t pc;
                size_t code_size;
                size_t data_size;
                size_t data_offset;
                void *data;
                const uint8_t *code;
                uint b_edges;
                uint f_edges;
                bool b_end;
                bool f_end;
                uint b_count;
                uint b_insn_count;
                uint f_insn_count;
                string b_trait;
                string b_bytes;
                string f_trait;
                string f_bytes;
                vector<uint64_t> blocks;
                vector<uint64_t> functions;
                vector<uint64_t> visited;
            };
            struct Section sections[DECOMPILER_REV_MAX_SECTIONS];
            Common common;
            DecompilerREV();
            bool Setup(cs_arch arch, cs_mode mode, uint index);
            void ClearBlock(uint index);
            void ClearTrait(uint index);
            void AddEdges(uint count, uint index);
            void CollectBlockTrait(uint index);
            void CollectFunctionTrait(uint index);
            void PrintTraits(bool pretty);
            void WriteTraits(char *file_path, bool pretty);
            uint Decompile(void *data, size_t data_size, size_t data_offset, uint index);
            void Seek(uint offset, uint index);
            ~DecompilerREV();

    };
}
#endif
