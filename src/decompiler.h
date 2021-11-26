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

#ifndef DECOMPILER_H
#define DECOMPILER_H

#define DECOMPILER_TYPE_FUNCS 0
#define DECOMPILER_TYPE_BLCKS 1
#define DECOMPILER_TYPE_UNSET 2
#define DECOMPILER_TYPE_ALL   3

#define DECOMPILER_MAX_INSN 0xfff

#define DECOMPILER_MAX_SECTIONS 256

using namespace std;
using json = nlohmann::json;

// Needs Refactoring

class Decompiler{
    private:
        struct Section {
            json traits;
            vector<uint64_t> visited;
        };
        string sha256(const char *trait){
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, trait, strlen(trait));
            SHA256_Final(hash, &ctx);
            string bytes = hexdump_be(&hash, SHA256_DIGEST_LENGTH, false);
            return rs(bytes);
        }
        float entropy(string trait){
            vector<char> bytes = t2c(trait);
            float result = 0;
            map<char,int> frequencies;
            for (char c : bytes){
                frequencies[c]++;
            }
            for (pair<char,int> p : frequencies) {
                float freq = static_cast<float>( p.second ) / bytes.size();
                result -= freq * log2(freq) ;
            }
            return result;
        }
        vector<char> t2c(string trait){
            trait = rs(rwc(trait));
            vector<char> bytes;
            for (int i = 0; i < trait.length(); i = i + 2){
                const char *s_byte = trait.substr(i, 2).c_str();
                unsigned char byte = (char)strtol(s_byte, NULL, 16);
                bytes.push_back(byte);
            }
            return bytes;
        }
        string rs(string s){
            // remove space
            string::iterator end_pos = remove(s.begin(), s.end(), ' ');
            s.erase(end_pos, s.end());
            return s;
        }
        string rwc(string s){
            // Remove Wildcard
            string::iterator end_pos = remove(s.begin(), s.end(), '?');
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
        string hexdump_be(const void *data, size_t size, bool cont){
            stringstream bytes;
            bytes << "";
            const unsigned char *local_pc = (const unsigned char *)data;
            for (int i = 0; i < size; i++){
                bytes << hex << setfill('0') << setw(2) << (unsigned uint32_t)local_pc[i] << " ";
            }
            if (cont == true){
                bytes << " ";
            }
            return bytes.str();
        }
        string hexdump_mem_disp(uint64_t disp){
            stringstream bytes;
            const unsigned char *local_pc = (const unsigned char *)&disp;
            for (int i = 0; i < sizeof(disp) -1 ; i++){
                if (local_pc[i] != 0 && local_pc[i] != 255){
                    bytes << hex << setfill('0') << setw(2) << (unsigned uint32_t)local_pc[i] << " ";
                }
            }
            return rtrim(bytes.str());
        }
        string wildcard_bytes(string bytes, string sub_bytes){
            bytes = rtrim(bytes);
            size_t index = bytes.find(sub_bytes, 0);
            if (index == string::npos){
                return bytes;
            }
            for (int i = index; i < bytes.length(); i = i + 3){
                bytes.replace(i, 2, "??");
            }
            return bytes;
        }

        string wildcard_all(string bytes){
            bytes = rtrim(bytes);
            for (int i = 0; i < bytes.length(); i = i + 3){
                bytes.replace(i, 2, "??");
            }
            return bytes + " ";
        }

        json GetTraits(){
            json result;
            for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++){
                if (sections[i].traits.is_null() == false){
                    if (sections[i].traits.is_null() == false){
                        for (int j = 0; j < sections[i].traits.size(); j++){
                            result.push_back(sections[i].traits[j]);
                        }
                    }
                }
            }
            return result;
        }
    public:
        csh handle;
        cs_err status;
        uint64_t pc;
        struct Section sections[DECOMPILER_MAX_SECTIONS];
        Decompiler(){
            pc = 0;
        }
        bool Setup(cs_arch arch, cs_mode mode){
            status = cs_open(arch, mode, &handle);
            if (status != CS_ERR_OK){
                return false;
            }
            status = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            if (status != CS_ERR_OK){
                return false;
            }
            return true;
        }
        int x86_64(void *data, size_t data_size, size_t data_offset, uint index){
            const uint8_t *code = (uint8_t *)data;
            json trait;
            size_t code_size = data_size;
            uint f_edges = 0;
            uint b_edges = 0;
            uint insn_size = 0;
            bool f_end = false;
            uint f_count = 0;
            uint f_insn_count = 0;
            string f_bytes;
            string f_trait;
            bool b_end = false;
            uint b_count = 0;
            uint b_insn_count = 0;
            string b_bytes;
            string b_trait;
            bool disasm = false;
            string o_trait;
            cs_insn *insn = cs_malloc(handle);
            while (true){
                bool wildcard_insn = false;
                disasm = cs_disasm_iter(handle, &code, &code_size, &pc, insn);
                if (disasm == false && pc >= data_size){
                    break;
                }
                if (disasm == false && pc < data_size){
                    // realign code and data for decompiler
                    pc++;
                    code_size = data_size - pc + 1;
                    memmove(data, code+1, code_size);
                    code = (uint8_t *)data;
                    f_trait.clear();
                    f_bytes.clear();
                    f_end = false;
                    f_edges = 0;
                    f_insn_count = 0;
                    b_count = 0;
                    o_trait.clear();
                    if (b_bytes.length() > 0){
                        goto collect_block;
                    }
                    b_trait.clear();
                    b_bytes.clear();
                    b_end = false;
                    b_insn_count = 0;
                    b_edges = 0;
                    continue;
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
                        // conditional
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JL:
                        // conditional
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JLE:
                        // conditional
                        f_edges = f_edges + 2;
                        b_edges = b_edges + 2;
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JG:
                        // conditional
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
                        b_end = true;
                        break;
                    case X86_INS_RETF:
                        f_count++;
                        f_end = true;
                        b_end = true;
                        break;
                    case X86_INS_RETFQ:
                        f_count++;
                        f_end = true;
                        b_end = true;
                        break;
                    case X86_INS_IRET:
                        f_count++;
                        f_end = true;
                        b_end = true;
                        break;
                    case X86_INS_IRETD:
                        f_count++;
                        f_end = true;
                        b_end = true;
                        break;
                    case X86_INS_IRETQ:
                        f_count++;
                        f_end = true;
                        b_end = true;
                        break;
                    case X86_INS_NOP:
                        wildcard_insn = true;
                        break;
                }

                // Parse Operands
                for (int j = 0; j < insn->detail->x86.op_count; j++){
                    cs_x86_op operand = insn->detail->x86.operands[j];
                    switch(operand.type){
                        case X86_OP_MEM:
                            // Wildcard Memory Operands
                            {
                                if (operand.mem.disp != 0){
                                    o_trait = wildcard_bytes(hexdump_be(insn->bytes, insn->size, false),
                                    hexdump_mem_disp(operand.mem.disp));
                                }
                                break;
                            }

                        case X86_OP_IMM:
                            // Wildcard Immutable Operands / Scalars
                            {
                                string imm = hexdump_mem_disp(operand.imm);
                                string instr = hexdump_be(insn->bytes, insn->size, false);
                                if (imm.length() > 0){
                                    o_trait = wildcard_bytes(instr, imm);
                                }
                                break;
                            }
                        default:
                            break;
                    }
                }
                if (wildcard_insn == true){
                    b_trait = b_trait + wildcard_all(hexdump_be(insn->bytes, insn->size, false));
                    f_trait = f_trait + wildcard_all(hexdump_be(insn->bytes, insn->size, false));
                    wildcard_insn = false;
                } else if (o_trait.length() > 0){
                    o_trait = rtrim(o_trait);
                    b_trait = b_trait + o_trait + " ";
                    f_trait = f_trait + o_trait + " ";
                    o_trait.clear();
                } else {
                    b_trait = b_trait + hexdump_be(insn->bytes, insn->size, false);
                    f_trait = f_trait + hexdump_be(insn->bytes, insn->size, false);
                }
                b_bytes = b_bytes + hexdump_be(insn->bytes, insn->size, false);
                b_insn_count++;
                f_bytes = f_bytes + hexdump_be(insn->bytes, insn->size, false);
                f_insn_count++;
                insn_size = insn->size;
                if (b_end == true && b_bytes.length() > 0){
                    collect_block:
                    trait["type"] = "block";
                    trait["bytes_sha256"] = sha256(rtrim(b_bytes).c_str());
                    trait["bytes"] = rtrim(b_bytes);
                    trait["size"] = trait_size(trait["bytes"]);
                    trait["instructions"] = b_insn_count;
                    trait["blocks"] = 1;
                    if (disasm == false){
                        trait["offset"] = data_offset + pc - (uint)trait["size"] - 1;
                    } else {
                        trait["offset"] = data_offset + pc - (uint)trait["size"];
                    }
                    trait["average_instructions_per_block"] = b_insn_count / 1;
                    trait["edges"] = b_edges;
                    trait["cyclomatic_complexity"] = b_edges - 1 + 2;
                    trait["bytes_entropy"] = entropy(trait["bytes"].get<string>());
                    trait["trait"] = rtrim(b_trait);
                    trait["trait_entropy"] = entropy(trait["trait"].get<string>());
                    trait["trait_sha256"] = sha256(rtrim(b_trait).c_str());
                    b_trait.clear();
                    b_bytes.clear();
                    b_end = false;
                    b_insn_count = 0;
                    b_edges = 0;
                    sections[index].traits.push_back(trait);
                    sections[index].visited.push_back(trait["offset"].get<uint64_t>());
                    trait.clear();
                }
                if (f_end == true && f_bytes.length() > 0){
                    trait["type"] = "function";
                    trait["bytes_sha256"] = sha256(rtrim(f_bytes).c_str());
                    trait["bytes"] = rtrim(f_bytes);
                    trait["bytes_entropy"] = entropy(trait["bytes"].get<string>());
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
                    trait["offset"] = data_offset + pc - (uint)trait["size"];
                    trait["edges"] = f_edges;
                    trait["trait"] = rtrim(f_trait);
                    trait["trait_entropy"] = entropy(trait["trait"].get<string>());
                    trait["trait_sha256"] = sha256(rtrim(f_trait).c_str());
                    f_trait.clear();
                    sections[index].traits.push_back(trait);
                    sections[index].visited.push_back(trait["offset"].get<uint64_t>());
                    f_bytes.clear();
                    f_end = false;
                    f_edges = 0;
                    f_insn_count = 0;
                    b_count = 0;
                    trait.clear();
                }
                //printf("pos: %ld,%ld\n", pc, data_size);
            }
            cs_free(insn, 1);
            return pc;
        }
        void PrintTraits(bool pretty){
            json traits = GetTraits();
            if (pretty == false){
                cout << traits.dump() << endl;
            } else {
                cout << traits.dump(4) << endl;
            }
        }
        void WriteTraits(char *file_path, bool pretty){
            FILE *fd = fopen(file_path, "w");
            string traits;
            if (pretty == false){
                traits = GetTraits().dump();
            } else {
                traits = GetTraits().dump(4);
            }
            if (traits.length() > 0){
                traits = traits + '\n';
            }
            fwrite(traits.c_str(), sizeof(char), traits.length(), fd);
            fclose(fd);
        }
        ~Decompiler(){
            cs_close(&handle);
            pc = 0;
        }
};

#endif
