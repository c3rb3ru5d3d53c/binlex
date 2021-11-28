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
#include "decompiler_rev.hpp"

using namespace std;
using json = nlohmann::json;


DecompilerREV(){
    printf("Constructor\n");
}

// Refactored Decompiler C++
// Should be more arch agnostic

// class DecompilerREV{
//     private:
//         struct Section {
//             json traits;
//             uint offset;
//             uint64_t pc;
//             size_t code_size;
//             size_t data_size;
//             size_t data_offset;
//             void *data;
//             const uint8_t *code;
//             uint b_edges;
//             uint f_edges;
//             bool b_end;
//             bool f_end;
//             uint b_count;
//             uint b_insn_count;
//             uint f_insn_count;
//             string b_trait;
//             string b_bytes;
//             string f_trait;
//             string f_bytes;
//             vector<uint64_t> blocks;
//             vector<uint64_t> functions;
//             vector<uint64_t> visited;
//         };
//         json GetTraits(){
//             json result;
//             for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++){
//                 if (sections[i].traits.is_null() == false){
//                     if (sections[i].traits.is_null() == false){
//                         for (int j = 0; j < sections[i].traits.size(); j++){
//                             result.push_back(sections[i].traits[j]);
//                         }
//                     }
//                 }
//             }
//             return result;
//         }
//     public:
//         csh handle;
//         cs_err status;
//         struct Section sections[DECOMPILER_REV_MAX_SECTIONS];
//         DecompilerREV(){
//             Cleanup();
//         }
//         void Cleanup(){
//             for (int i = 0; i < DECOMPILER_REV_MAX_SECTIONS; i++){
//                 sections[i].traits.clear();
//                 sections[i].offset = 0;
//                 sections[i].pc = 0;
//                 sections[i].code_size = 0;
//                 sections[i].data_size = 0;
//                 sections[i].data_offset = 0;
//                 sections[i].data = NULL;
//                 sections[i].code = NULL;
//                 sections[i].b_edges = 0;
//                 sections[i].f_edges = 0;
//                 sections[i].b_end = false;
//                 sections[i].f_end = false;
//                 sections[i].b_count = 0;
//                 sections[i].b_insn_count = 0;
//                 sections[i].f_insn_count = 0;
//                 sections[i].b_trait.clear();
//                 sections[i].b_bytes.clear();
//                 sections[i].f_trait.clear();
//                 sections[i].f_bytes.clear();
//                 sections[i].blocks.clear();
//                 sections[i].functions.clear();
//                 sections[i].visited.clear();
//             }
//         }
//         bool Setup(cs_arch arch, cs_mode mode){
//             status = cs_open(arch, mode, &handle);
//             if (status != CS_ERR_OK){
//                 return false;
//             }
//             status = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
//             if (status != CS_ERR_OK){
//                 return false;
//             }
//             return true;
//         }
//         void Seek(uint offset, uint index){
//             sections[index].pc = offset;
//             sections[index].code_size = sections[index].data_size - offset;
//             memmove(sections[index].data, sections[index].code + sections[index].pc, sections[index].code_size);
//             sections[index].code = (uint8_t *)sections[index].data;
//         }
//         void ClearBlock(uint index){
//             sections[index].b_trait.clear();
//             sections[index].b_bytes.clear();
//             sections[index].b_edges = 0;
//             sections[index].b_insn_count = 0;
//             sections[index].b_end = false;
//         }
//         void CollectBlockTrait(uint index){
//             json trait;
//             trait["type"] = "block";
//             trait["trait"] = TrimRight(sections[index].b_trait);
//             trait["edges"] = sections[index].b_edges;
//             trait["bytes"] = TrimRight(sections[index].b_bytes);
//             trait["size"] = GetByteSize(sections[index].b_bytes);
//             trait["instructions"] = sections[index].b_insn_count;
//             trait["bytes_entropy"] = Entropy(sections[index].b_bytes);
//             sections[index].traits.push_back(trait);
//             ClearBlock(index);
//         }
//         void CollectFunctionTrait(uint index){
//             json trait;
//             trait["type"] = "function";
//             trait["trait"] = TrimRight(sections[index].f_trait);
//             trait["edges"] = sections[index].f_edges;
//             trait["bytes"] = TrimRight(sections[index].f_bytes);
//             trait["size"] = GetByteSize(sections[index].f_bytes);
//             trait["instructions"] = sections[index].f_insn_count;
//             sections[index].traits.push_back(trait);
//             ClearTrait(index);
//         }
//         void ClearTrait(uint index){
//             sections[index].f_trait.clear();
//             sections[index].f_bytes.clear();
//             sections[index].f_edges = 0;
//             sections[index].f_insn_count = 0;
//             sections[index].f_end = false;
//         }
//         void AppendWildcards(uint index, uint count){
//             for (int i = 0; i < count; i++){
//                 sections[index].f_trait + "?? ";
//                 sections[index].b_trait + "?? ";
//             }
//         }
//         void AppendBytes(void *data, size_t data_size, uint index){
//             sections[index].b_bytes = sections[index].b_bytes + HexdumpBE(data, data_size) + " ";
//             sections[index].f_bytes = sections[index].f_bytes + HexdumpBE(data, data_size) + " ";
//         }
//         void AppendTrait(string trait, uint index){
//             sections[index].b_trait = sections[index].b_trait + trait + " ";
//             sections[index].f_trait = sections[index].f_trait + trait + " ";
//         }
//         void AppendTraitBytes(void *data, size_t data_size, uint index){
//             sections[index].b_trait = sections[index].b_trait + HexdumpBE(data, data_size) + " ";
//             sections[index].f_trait = sections[index].f_trait + HexdumpBE(data, data_size) + " ";
//         }
//         void AppendAllBytes(void *data, size_t data_size, uint index){
//             AppendTraitBytes(data, data_size, index);
//             AppendBytes(data, data_size, index);
//         }
//         void CountBlock(uint index){
//             sections[index].b_count++;
//             sections[index].b_end = true;
//         }
//         void CountBlockInsn(uint index){
//             sections[index].b_insn_count++;
//         }
//         void CountFunctionInsn(uint index){
//             sections[index].f_insn_count++;
//         }
//         void CountAllInsn(uint index){
//             CountBlockInsn(index);
//             CountFunctionInsn(index);
//         }
//         string HexdumpBE(const void *data, size_t size){
//             stringstream bytes;
//             bytes << "";
//             const unsigned char *local_pc = (const unsigned char *)data;
//             for (int i = 0; i < size; i++){
//                 bytes << hex << setfill('0') << setw(2) << (unsigned uint32_t)local_pc[i] << " ";
//             }
//             return TrimRight(bytes.str());
//         }
//         string HexdumpMemDisp(uint64_t disp){
//             stringstream bytes;
//             const unsigned char *local_pc = (const unsigned char *)&disp;
//             for (int i = 0; i < sizeof(disp) -1 ; i++){
//                 if (local_pc[i] != 0 && local_pc[i] != 255){
//                     bytes << hex << setfill('0') << setw(2) << (unsigned uint32_t)local_pc[i] << " ";
//                 }
//             }
//             return TrimRight(bytes.str());
//         }
//         void AddEdges(uint count, uint index){
//             sections[index].b_edges = sections[index].b_edges + count;
//             sections[index].f_edges = sections[index].f_edges + count;
//         }
//         string AppendWildcardBytes(string bytes, string sub_bytes){
//             return WildcardBytes(bytes, sub_bytes) + " ";
//         }
//         string WildcardBytes(string bytes, string sub_bytes){
//             size_t index = bytes.find(sub_bytes, 0);
//             if (index == string::npos){
//                 return bytes;
//             }
//             for (int i = index; i < bytes.length(); i = i + 3){
//                 bytes.replace(i, 2, "??");
//             }
//             return bytes;
//         }
//         string WildcardAll(string bytes){
//             for (int i = 0; i < bytes.length(); i = i + 3){
//                 bytes.replace(i, 2, "??");
//             }
//             return bytes;
//         }
//         string TrimRight(const std::string &s){
//             const string whitespace = " \n\r\t\f\v";
//             size_t end = s.find_last_not_of(whitespace);
//             return (end == std::string::npos) ? "" : s.substr(0, end + 1);
//         }
//         string RemoveSpaces(string s){
//             string::iterator end_pos = remove(s.begin(), s.end(), ' ');
//             s.erase(end_pos, s.end());
//             return s;
//         }
//         string RemoveWildcards(string s){
//             string::iterator end_pos = remove(s.begin(), s.end(), '?');
//             s.erase(end_pos, s.end());
//             return s;
//         }
//         uint GetByteSize(string s){
//             return RemoveSpaces(s).length() / 2;
//         }
//         string GetTraitSHA256(const char *trait){
//             unsigned char hash[SHA256_DIGEST_LENGTH];
//             SHA256_CTX ctx;
//             SHA256_Init(&ctx);
//             SHA256_Update(&ctx, trait, strlen(trait));
//             SHA256_Final(hash, &ctx);
//             string bytes = HexdumpBE(&hash, SHA256_DIGEST_LENGTH);
//             return RemoveSpaces(bytes);
//         }
//         float Entropy(string trait){
//             vector<char> bytes = TraitToChar(trait);
//             float result = 0;
//             map<char,int> frequencies;
//             for (char c : bytes){
//                 frequencies[c]++;
//             }
//             for (pair<char,int> p : frequencies) {
//                 float freq = static_cast<float>( p.second ) / bytes.size();
//                 result -= freq * log2(freq) ;
//             }
//             return result;
//         }
//         vector<char> TraitToChar(string trait){
//             trait = RemoveSpaces(RemoveWildcards(trait));
//             vector<char> bytes;
//             for (int i = 0; i < trait.length(); i = i + 2){
//                 const char *s_byte = trait.substr(i, 2).c_str();
//                 unsigned char byte = (char)strtol(s_byte, NULL, 16);
//                 bytes.push_back(byte);
//             }
//             return bytes;
//         }
//         void AppendOperandsTraitBytes(cs_insn *insn, bool conditional, uint index){
//             string o_trait;
//             for (int j = 0; j < insn->detail->x86.op_count; j++){
//                 cs_x86_op operand = insn->detail->x86.operands[j];
//                 switch(operand.type){
//                     case X86_OP_MEM:
//                         // Wildcard Memory Operands
//                         {
//                             if (operand.mem.disp != 0){
//                                 o_trait = WildcardBytes(HexdumpBE(insn->bytes, insn->size), HexdumpMemDisp(operand.mem.disp));
//                             }
//                             break;
//                         }

//                     case X86_OP_IMM:
//                         // Wildcard Immutable Operands / Scalars
//                         {
//                             string imm = HexdumpMemDisp(operand.imm);
//                             string instr = HexdumpBE(insn->bytes, insn->size);
//                             if (imm.length() > 0){
//                                 o_trait = WildcardBytes(instr, imm);
//                             }
//                             break;
//                         }
//                     default:
//                         break;
//                 }
//             }
//             AppendTrait(TrimRight(o_trait), index);
//             AppendBytes(insn->bytes, insn->size, index);
//             o_trait.clear();
//         }
//         uint Decompile(void *data, size_t data_size, size_t data_offset, uint index){
//             sections[index].pc = 0;
//             sections[index].data = data;
//             sections[index].data_size = data_size;
//             sections[index].data_offset = data_offset;
//             sections[index].code = (uint8_t *)data;
//             cs_insn *insn = cs_malloc(handle);
//             while (true){
//                 if (sections[index].pc >= data_size){
//                     break;
//                 }
//                 if (cs_disasm_iter(handle, &sections[index].code, &sections[index].code_size, &sections[index].pc, insn) == false){
//                     Seek(sections[index].pc + 1, index);
//                     AppendWildcards(index, 1);
//                     AppendBytes(sections[index].data, 1, index);
//                     continue;
//                 }
//                 AppendBytes(insn->bytes, insn->size, index);
//                 // switch(insn->id){
//                 //     case X86_INS_JMP:
//                 //         AddEdges(1, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JNE:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JNO:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);\
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JNP:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JL:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JLE:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JG:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JGE:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JE:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JECXZ:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JCXZ:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JB:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JBE:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JA:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JAE:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JNS:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JO:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JP:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JRCXZ:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_JS:
//                 //         AddEdges(2, index);
//                 //         CountBlock(index);
//                 //         AppendOperandsTraitBytes(insn, true, index);
//                 //         CountAllInsn(index);
//                 //         CollectBlockTrait(index);
//                 //         continue;
//                 //     case X86_INS_RET:
//                 //         AppendAllBytes(insn->bytes, insn->size, index);
//                 //         CountAllInsn(index);
//                 //         CollectFunctionTrait(index);
//                 //         continue;
//                 //     case X86_INS_RETF:
//                 //         AppendAllBytes(insn->bytes, insn->size, index);
//                 //         CountAllInsn(index);
//                 //         CollectFunctionTrait(index);
//                 //         continue;
//                 //     case X86_INS_RETFQ:
//                 //         AppendAllBytes(insn->bytes, insn->size, index);
//                 //         CountAllInsn(index);
//                 //         CollectFunctionTrait(index);
//                 //         continue;
//                 //     case X86_INS_IRET:
//                 //         AppendAllBytes(insn->bytes, insn->size, index);
//                 //         CountAllInsn(index);
//                 //         CollectFunctionTrait(index);
//                 //         continue;
//                 //     case X86_INS_IRETD:
//                 //        AppendAllBytes(insn->bytes, insn->size, index);
//                 //        CountAllInsn(index);
//                 //        CollectFunctionTrait(index);
//                 //         continue;
//                 //     case X86_INS_IRETQ:
//                 //         AppendAllBytes(insn->bytes, insn->size, index);
//                 //         CountAllInsn(index);
//                 //         CollectFunctionTrait(index);
//                 //         continue;
//                 //     case X86_INS_NOP:
//                 //         AppendWildcards(insn->size, index);
//                 //         CountAllInsn(index);
//                 //         CollectFunctionTrait(index);
//                 //         continue;
//                 //     default:
//                 //         break;
//                 // }
//                 // if (insn->detail->x86.op_count > 0){
//                 //     AppendOperandsTraitBytes(insn, true, index);
//                 // } else {
//                 //     AppendAllBytes(insn->bytes, insn->size, index);
//                 // }
//                 // CountAllInsn(index);
//                 // printf("pc: %ld, %ld\n", sections[index].pc, sections[index].data_size);
//             }
//             cout << sections[index].b_bytes << endl;
//             cs_free(insn, 1);
//             return sections[index].pc;
//         }
//         void PrintTraits(bool pretty){
//             json traits = GetTraits();
//             if (pretty == false){
//                 cout << traits.dump() << endl;
//             } else {
//                 cout << traits.dump(4) << endl;
//             }
//         }
//         void WriteTraits(char *file_path, bool pretty){
//             FILE *fd = fopen(file_path, "w");
//             string traits;
//             if (pretty == false){
//                 traits = GetTraits().dump();
//             } else {
//                 traits = GetTraits().dump(4);
//             }
//             if (traits.length() > 0){
//                 traits = traits + '\n';
//             }
//             fwrite(traits.c_str(), sizeof(char), traits.length(), fd);
//             fclose(fd);
//         }
//         ~DecompilerREV(){
//             //Cleanup();
//             cs_close(&handle);
//         }
// };
