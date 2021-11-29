#include <vector>
#include "json.h"

#ifndef DECOMPILER_H
#define DECOMPILER_H

#define DECOMPILER_TYPE_FUNCS 0
#define DECOMPILER_TYPE_BLCKS 1
#define DECOMPILER_TYPE_UNSET 2
#define DECOMPILER_TYPE_ALL   3

#define DECOMPILER_MAX_SECTIONS 256

using namespace std;
using json = nlohmann::json;

namespace binlex{
    class Decompiler{
        private:
            struct Section {
                json traits;
                vector<uint64_t> visited;
            };
            string sha256(const char *trait);
            float entropy(string trait);
            vector<char> t2c(string trait);
            string rs(string s);
            string rwc(string s);
            uint trait_size(string s);
            string rtrim(const std::string &s);
            string hexdump_be(const void *data, size_t size, bool cont);
            string hexdump_mem_disp(uint64_t disp);
            string wildcard_bytes(string bytes, string sub_bytes);
            string wildcard_all(string bytes);
            json GetTraits();
        public:
            csh handle;
            cs_err status;
            uint64_t pc;
            struct Section sections[DECOMPILER_MAX_SECTIONS];
            Decompiler();
            bool Setup(cs_arch arch, cs_mode mode);
            int x86_64(void *data, size_t data_size, size_t data_offset, uint index);
            void PrintTraits(bool pretty);
            void WriteTraits(char *file_path, bool pretty);
            ~Decompiler();
    };
}
#endif
