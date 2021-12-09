#include <vector>
#include <capstone/capstone.h>
#include "common.h"

#ifndef DECOMPILER_REV_H
#define DECOMPILER_REV_H

#define DECOMPILER_REV_MAX_SECTIONS 256

#define DECOMPILER_REV_OPERAND_TYPE_BLOCK    0
#define DECOMPILER_REV_OPERAND_TYPE_FUNCTION 1

using namespace std;

namespace binlex {
    class DecompilerREV: public Common {
        private:
            typedef struct{
                string type;
                string bytes;
                string trait;
                uint edges;
                uint blocks;
                uint insns;
            } trait;
        public:
            struct Section {
                csh handle;
                cs_err status;
                uint offset;
                uint64_t pc;
                trait *traits;
                uint traits_count;
                void *data;
                size_t data_size;
                vector<uint64_t> blocks;
                vector<uint64_t> functions;
                vector<uint64_t> visited;
            };
            struct Section sections[DECOMPILER_REV_MAX_SECTIONS];
            DecompilerREV();
            /**
            Set up Capstone Decompiler Architecure and Mode
            @param arch Capstone Decompiler Architecure
            @param cs_mode Capstone Mode
            @param index section index
            */
            bool Setup(cs_arch arch, cs_mode mode, uint index);
            /**
            Collect Operands for Processing
            @param insn the instruction
            @param operand_type the operand type
            @param index the section index
            @returns bool
            */
            bool CollectOperands(cs_insn *insn, int operand_type, uint index);
            /**
            Collect Instructions for Processing
            @param insn the instruction
            @param index the section index
            @returns bool
            */
            bool CollectInsn(cs_insn *insn, uint index);
            /**
            Collect Immutable Operands
            @param imm immutable value
            @param operand_type the operand type
            @param index the section index
            */
            void CollectImm(int64_t imm, int operand_type, uint index);
            /**
            Decompiles Target Data
            @param data pointer to data
            @param data_size size of data
            @param data_offset include section offset
            @param index the section index
            @returns program counter position
            */
            uint Decompile(void *data, size_t data_size, size_t data_offset, uint index);
            /**
            Allocate Additional Traits
            @param count number of additional traits to allocate
            @param index the section index
            @return bool
            */
            /**
            Checks if the Instruction is an Ending Instruction
            @param insn the instruction
            @return bool
            */
            bool IsEndInsn(cs_insn *insn);
            bool AllocTraits(uint count, uint index);
            //void Seek(uint offset, uint index);
            ~DecompilerREV();

    };
}
#endif
