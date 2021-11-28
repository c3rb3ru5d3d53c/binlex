#ifndef DECOMPILER_REV_H
#define DECOMPILER_REV_H

#define DECOMPILER_REV_TYPE_FUNCS 0
#define DECOMPILER_REV_TYPE_BLCKS 1
#define DECOMPILER_REV_TYPE_UNSET 2
#define DECOMPILER_REV_TYPE_ALL   3

#define DECOMPILER_REV_MAX_SECTIONS 256

class DecompilerREV{
    public:
        DecompilerREV();
        struct Section {
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
};

#endif
