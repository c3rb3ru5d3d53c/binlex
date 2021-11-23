#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <iomanip>
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
        bool x86_64(int type, void *data, size_t data_size, int index){
            const uint8_t *code = (uint8_t *)data;
            cs_insn *insn = cs_malloc(engine.cs);
            bool f_end = false;
            uint f_count = 0;
            string f_trait;
            bool b_end = false;
            uint b_count = 0;
            string b_trait;
            while (cs_disasm_iter(engine.cs, &code, &data_size, &engine.pc, insn)){
                //string bytes = hexdump_be(insn->bytes, insn->size);
                switch(insn->id){
                    case X86_INS_JMP:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JNE:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JNO:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JNP:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JL:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JLE:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JG:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JGE:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JE:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JECXZ:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JCXZ:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JB:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JBE:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JA:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JAE:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JNS:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JO:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JP:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JRCXZ:
                        b_count++;
                        b_end = true;
                        break;
                    case X86_INS_JS:
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
                b_trait = b_trait + hexdump_be(insn->bytes, insn->size);
                if (b_end == true && b_trait.length() > 0){
                    cout << rtrim(b_trait) << endl;
                    b_trait.clear();
                    b_end = false;
                }
                // f_trait = f_trait + hexdump_be(insn->bytes, insn->size);
                // if (f_end == true && f_trait.length() > 0){
                //     cout << rtrim(f_trait) << endl;
                //     f_trait.clear();
                //     f_end = true;
                // }
            }
            cs_free(insn, 1);
            return true;
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
