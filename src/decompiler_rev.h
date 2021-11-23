#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>
#include <math.h>
#include <capstone/capstone.h>
#include "json.h"

#ifndef DECOMPILER_REV_H
#define DECOMPILER_REV_H

#define DECOMPILER_REV_ERROR_CHECK if(CheckError() == false){return false;}else{return true;}

#define DECOMPILER_REV_TYPE_FUNCS 0
#define DECOMPILER_REV_TYPE_BLCKS 1
#define DECOMPILER_REV_TYPE_UNSET 2
#define DECOMPILER_REV_TYPE_ALL   3

#define DECOMPILER_REV_MAX_INSN 0xfff

#define DECOMPILER_REV_MAX_SECTIONS 256

using namespace std;
using json = nlohmann::json;

class DecompilerREV{
    private:
        struct Section {
            json traits;
            vector<int> visited;
        };
        string sha256(const char *trait){
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, trait, strlen(trait));
            SHA256_Final(hash, &ctx);
            string bytes = hexdump_be(&hash, SHA256_DIGEST_LENGTH);
            return rs(bytes);
        }
        int entropy(void *data, size_t size){
            float entropy;
            float count;
            const unsigned char *pc = (const unsigned char *)data;
            for (int i = 0; i < size; i++){
                if (pc[i] != 0){
                    count = (float) pc[i] / (float) size;
                    entropy += -count * log2f(count);
                }
            }
            return entropy;
        }
        vector<char> h2b(string& s) {
            s = rs(s);
            vector<char> bytes;
            for (unsigned int i = 0; i < s.length(); i += 2) {
                string byteString = s.substr(i, 2);
                char byte = (char)strtol(byteString.c_str(), NULL, 16);
                bytes.push_back(byte);
            }
            return bytes;
        }
        string rs(string s){
            string::iterator end_pos = remove(s.begin(), s.end(), ' ');
            s.erase(end_pos, s.end());
            return s;
        }
        uint trait_size(string s){
            return rs(s).length() / 2;
        }
        string rtrim(const std::string &s){
            const string whitespace = " \n\r\t\f\v";
            size_t end = s.find_last_not_of(whitespace);
            return (end == std::string::npos) ? "" : s.substr(0, end + 1);
        }
        string hexdump_be(const void *data, size_t size){
            stringstream bytes;
            bytes << "";
            const unsigned char *pc = (const unsigned char *)data;
            for (int i = 0; i < size; i++){
                bytes << hex << setfill('0') << setw(2) << (unsigned uint32_t)pc[i] << " ";
            }
            return bytes.str();
        }
        bool CheckError(){
            if (engine.error != CS_ERR_OK){
                return false;
            }
            return true;
        }
    public:
        struct {
            cs_err error;
            csh cs;
            uint64_t pc;
        } engine;
        struct Section sections[DECOMPILER_REV_MAX_SECTIONS];
        DecompilerREV(){
            engine.pc = 0;
        }
        bool Setup(cs_arch arch, cs_mode mode){
            engine.error = cs_open(arch, mode, &engine.cs);
            DECOMPILER_REV_ERROR_CHECK
            engine.error = cs_option(engine.cs, CS_OPT_DETAIL, CS_OPT_ON);
            DECOMPILER_REV_ERROR_CHECK
        }
        bool x86_64(void *data, size_t data_size, size_t data_offset, uint index){
            const uint8_t *code = (uint8_t *)data;
            size_t code_size = data_size;
            cs_insn *insn = cs_malloc(engine.cs);
            uint f_edges = 0;
            uint b_edges = 0;
            uint insn_size = 0;
            bool f_end = false;
            uint f_count = 0;
            uint f_insn_count = 0;
            string f_bytes;
            bool b_end = false;
            uint b_count = 0;
            uint b_insn_count = 0;
            string b_bytes;
            bool disasm = false;
            json trait;
            while (true){
                disasm = cs_disasm_iter(engine.cs, &code, &code_size, &engine.pc, insn);
                if (disasm == false && engine.pc == data_size){
                    break;
                }
                if (disasm == false && engine.pc < data_size){
                    fprintf(stderr, "[x] decompile error at offset 0x%x", (uint)data_offset + (uint)engine.pc);
                    if (insn_size == 0){
                        engine.pc++;
                    } else {
                        engine.pc = engine.pc + insn_size;
                    }
                }
                switch(insn->id){
                    case X86_INS_JMP:
                        // non-conditional
                        f_edges++;
                        b_edges++;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JNE:
                        // conditional
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JNO:
                        // conditional
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JNP:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JL:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JLE:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JG:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JGE:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JE:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JECXZ:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JCXZ:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JB:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JBE:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JA:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JAE:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JNS:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JO:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JP:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JRCXZ:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JS:
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_RET:
                        f_count++;
                        f_end = true;
                        break;
                    case X86_INS_RETF:
                        f_count++;
                        f_end = true;
                        break;
                    case X86_INS_RETFQ:
                        f_count++;
                        f_end = true;
                        break;
                    case X86_INS_IRET:
                        f_count++;
                        f_end = true;
                        break;
                    case X86_INS_IRETD:
                        f_count++;
                        f_end = true;
                        break;
                    case X86_INS_IRETQ:
                        f_count++;
                        f_end = true;
                        break;
                }
                b_bytes = b_bytes + hexdump_be(insn->bytes, insn->size);
                b_insn_count++;
                if (b_end == true && b_bytes.length() > 0){
                    trait["type"] = "block";
                    trait["bytes_sha256"] = sha256(rtrim(b_bytes).c_str());
                    trait["bytes"] = rtrim(b_bytes);
                    trait["bytes_entropy"] = 0;
                    trait["size"] = trait_size(trait["bytes"]);
                    trait["instructions"] = b_insn_count;
                    trait["blocks"] = 1;
                    trait["offset"] = data_offset + engine.pc - (uint)trait["size"];
                    trait["average_instructions_per_block"] = b_insn_count / 1;
                    trait["edges"] = b_edges;
                    trait["cyclomatic_complexity"] = b_edges - 1 + 2;
                    b_bytes.clear();
                    b_end = false;
                    b_insn_count = 0;
                    b_edges = 0;
                    sections[index].traits.push_back(trait);
                    trait.clear();
                }
                f_bytes = f_bytes + hexdump_be(insn->bytes, insn->size);
                f_insn_count++;
                if (f_end == true && f_bytes.length() > 0){
                    trait["type"] = "function";
                    trait["bytes_sha256"] = sha256(rtrim(f_bytes).c_str());
                    trait["bytes"] = rtrim(f_bytes);
                    trait["bytes_entropy"] = 0;
                    trait["size"] = trait_size(trait["bytes"]);
                    trait["instructions"] = f_insn_count;
                    if (b_count == 0){
                        trait["blocks"] = 1;
                        trait["average_instructions_per_block"] = f_insn_count / 1;
                        trait["cyclomatic_complexity"] = f_edges - 1 + 2;
                    } else {
                        trait["blocks"] = b_count;
                        trait["average_instructions_per_block"] = f_insn_count / b_count;
                        trait["cyclomatic_complexity"] = f_edges - b_count + 2;
                    }
                    trait["offset"] = data_offset + engine.pc - (uint)trait["size"];
                    trait["edges"] = f_edges;

                    f_bytes.clear();
                    f_end = true;
                    f_edges = 0;
                    f_insn_count = 0;
                    b_count = 0;
                    sections[index].traits.push_back(trait);
                    trait.clear();
                }
                insn_size = insn->size;
            }
            cs_free(insn, 1);
            return true;
        }
        void PrintTraits(){
            for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++){
                if (sections[i].traits.is_null() == false){
                    cout << sections[0].traits.dump() << endl;
                }
            }
        }
        ~DecompilerREV(){
            cs_close(&engine.cs);
            engine.pc = 0;
        }
};

// while (true){
//     cs_disasm_iter(data, data_size, 0, insn);
//     if (sections[index].visited.size() > DECOMPILER_REV_MAX_INSN){
//          break;
//     }
// }

#endif
