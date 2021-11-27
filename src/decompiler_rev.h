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
            uint offset;
            uint64_t pc;
            size_t code_size;
            size_t data_size;
            void *data;
            const uint8_t *code;
            uint b_edges;
            uint f_edges;
            bool b_end;
            bool f_end;
            uint b_insn_count;
            uint f_insn_count;
            string b_trait;
            string b_bytes;
            string f_trait;
            string f_bytes;
            vector<uint64_t> b_visited;
            vector<uint64_t> f_visited;
        };
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
        struct Section sections[DECOMPILER_MAX_SECTIONS];
        Decompiler(){
            for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++){
                sections[i].pc = 0;
            }
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
        void Seek(uint offset, uint index){
            sections[index].pc = offset;
            sections[index].code_size = sections[index].data_size - offset;
            memmove(sections[index].data, sections[index].code + sections[index].pc, sections[index].code_size);
            sections[index].code = (uint8_t *)sections[index].data;
        }
        void ClearBlock(uint index){
            sections[index].b_edges = 0;
            sections[index].b_count = 0;
            sections[index].b_end = false;
            sections[index].b_insn_count = 0;
            sections[index].b_trait.clear();
            sections[index].b_bytes.clear();
        }
        void ClearTrait(uint index){
            sections[index].f_edges = 0;
            sections[index].f_count = 0;
            sections[index].f_end = false;
            sections[index].f_insn_count = 0;
            sections[index].f_trait.clear();
            sections[index].f_bytes.clear();
        }
        void AppendWildcards(uint index, uint count){
            for (int i = 0; i < count; i++){
                sections[index].f_trait + "?? ";
                sections[index].b_trait + "?? ";
            }
        }
        void AppendBytes(void *data, size_t data_size, uint index){
            sections[index].b_bytes = sections[index].b_bytes + HexdumpBE(data, data_size, index) + " ";
        }
        void AppendTrait(string trait){
            sections[index].b_trait = b_trait + trait + " ";
            sections[index].f_trait = f_trait + trait + " ";
        }
        void CountBlock(uint index){
            sections[index].b_count++;
            sections[index].b_end = true;
        }
        void CountFunction(uint index){
            sections[index].f_count++;
            sections[index].f_end = true;
            CountBlock(index);
        }
        string HexdumpBE(const void *data, size_t size){
            stringstream bytes;
            bytes << "";
            const unsigned char *local_pc = (const unsigned char *)data;
            for (int i = 0; i < size; i++){
                bytes << hex << setfill('0') << setw(2) << (unsigned uint32_t)local_pc[i] << " ";
            }
            return bytes.str();
        }
        string HexdumpMemDisp(uint64_t disp){
            stringstream bytes;
            const unsigned char *local_pc = (const unsigned char *)&disp;
            for (int i = 0; i < sizeof(disp) -1 ; i++){
                if (local_pc[i] != 0 && local_pc[i] != 255){
                    bytes << hex << setfill('0') << setw(2) << (unsigned uint32_t)local_pc[i] << " ";
                }
            }
            return TrimRight(bytes.str());
        }
        void AddEdges(uint count, uint index){
            sections[i].b_edges = sections[i].b_edges + count;
            sections[i].f_edges = sections[i].f_edges + count;
        }
        string AppendWildcardBytes(string bytes, string sub_bytes){
            return WildcardBytes(bytes, sub_bytes) + " ";
        }
        string WildcardBytes(string bytes, string sub_bytes){
            size_t index = bytes.find(sub_bytes, 0);
            if (index == string::npos){
                return bytes;
            }
            for (int i = index; i < bytes.length(); i = i + 3){
                bytes.replace(i, 2, "??");
            }
            return bytes;
        }
        string WildcardAll(string bytes){
            for (int i = 0; i < bytes.length(); i = i + 3){
                bytes.replace(i, 2, "??");
            }
            return bytes;
        }
        string TrimRight(const std::string &s){
            const string whitespace = " \n\r\t\f\v";
            size_t end = s.find_last_not_of(whitespace);
            return (end == std::string::npos) ? "" : s.substr(0, end + 1);
        }
        string RemoveSpaces(string s){
            string::iterator end_pos = remove(s.begin(), s.end(), ' ');
            s.erase(end_pos, s.end());
            return s;
        }
        uint GetByteSize(string s){
            return RemoveSpaces(s).length() / 2;
        }
        void AppendWildcardOperands(cs_insn insn, bool conditional, uint index){
            string o_trait;
            for (int j = 0; j < insn->detail->x86.op_count; j++){
                cs_x86_op operand = insn->detail->x86.operands[j];
                switch(operand.type){
                    case X86_OP_MEM:
                        // Wildcard Memory Operands
                        {
                            if (operand.mem.disp != 0){
                                o_trait = WildcardBytes(HexdumpBE(insn->bytes, insn->size), HexdumpMemDisp(operand.mem.disp));
                            }
                            break;
                        }

                    case X86_OP_IMM:
                        // Wildcard Immutable Operands / Scalars
                        {
                            string imm = hexdump_mem_disp(operand.imm);
                            string instr = hexdump_be(insn->bytes, insn->size, false);
                            if (imm.length() > 0){
                                o_trait = WildcardBytes(instr, imm);
                            }
                            break;
                        }
                    default:
                        break;
                }
            }
            AppendTrait(o_trait);
            o_trait.clear();
        }

        int Decompile(void *data, size_t data_size, size_t data_offset, uint index){
            sections[index].data = data;
            sections[index].data_size = data_size;
            sections[index].data_offset = data_offset;
            sections[index].code = (uint8_t *)data;
            cs_insn *insn = cs_malloc(handle);
            while (true){
                if (sections[index].pc >= data_size){
                    break;
                }
                if (cs_disasm_iter(handle, &code, &code_size, &properties[index].pc, insn) == false){
                    Seek(sections[index].pc + 1, index);
                    AppendWildcards(index, 1);
                    AppendBytes(sections[index].data, 1, index);
                    continue;
                }
                switch(insn->id){
                    case X86_INS_JMP:
                        AddEdges(1, index);
                        CountBlock();
                        break;
                    case X86_INS_JNE:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JNO:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JNP:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JL:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JLE:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JG:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JGE:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JE:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JECXZ:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JCXZ:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JB:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JBE:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JA:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JAE:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JNS:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JO:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JP:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JRCXZ:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_JS:
                        AddEdges(2, index);
                        CountBlock();
                        break;
                    case X86_INS_RET:
                        CountFunction(index);
                        break;
                    case X86_INS_RETF:
                        CountFunction(index);
                        break;
                    case X86_INS_RETFQ:
                        CountFunction(index);
                        break;
                    case X86_INS_IRET:
                        CountFunction(index);
                        break;
                    case X86_INS_IRETD:
                       CountFunction(index);
                        break;
                    case X86_INS_IRETQ:
                        CountFunction(index);
                        break;
                    case X86_INS_NOP:
                        AppendWildcards(1, index);
                        continue;
                    default:
                        break;
                }
            }
            cs_free(insn, 1);
            return pc;
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
                    case X86_INS_INVALID:
                        b_end = true;
                        f_end = true;
                        wildcard_insn = true;
                        break;
                    default:
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
            for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++){
                sections[i].pc = 0;
            }
            cs_close(&handle);
        }
};

#endif
