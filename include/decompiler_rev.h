#include <vector>
#include <queue>
#include <capstone/capstone.h>
#include "common.h"

#ifndef DECOMPILER_REV_H
#define DECOMPILER_REV_H

#define DECOMPILER_REV_MAX_SECTIONS 256

#define DECOMPILER_REV_OPERAND_TYPE_BLOCK    0
#define DECOMPILER_REV_OPERAND_TYPE_FUNCTION 1
#define DECOMPILER_REV_OPERAND_TYPE_UNSET    2

#define DECOMPILER_REV_THREADS 4

using namespace std;

namespace binlex {
    class DecompilerREV : public Common {
    private:
        typedef struct {
            string type;
            string bytes;
            string trait;
            uint edges;
            uint blocks;
            uint insns;
            uint size;
        } trait;
    public:
        struct Section {
            cs_arch arch;
            cs_mode mode;
            uint threads;
            uint offset;
            trait *traits;
            uint traits_count;
            void *data;
            size_t data_size;
            map<uint64_t, uint> addresses;
            map<uint64_t, int> visited;
            queue<uint64_t> discovered;
        };
        struct Section sections[DECOMPILER_REV_MAX_SECTIONS];
        DecompilerREV();
        /**
        Set up Capstone Decompiler Architecure and Mode
        @param arch Capstone Decompiler Architecure
        @param cs_mode Capstone Mode
        @param index section index
        */
        static void * Worker(void *args);
        bool Setup(cs_arch arch, cs_mode mode, uint index, uint threads);
        /**
        Collect Function and Conditional Operands for Processing
        @param insn the instruction
        @param operand_type the operand type
        @param index the section index
        @returns bool
        */
        static void CollectOperands(cs_insn* insn, int operand_type, struct Section *sections, uint index);
        /**
        Collect Instructions for Processing
        @param insn the instruction
        @param index the section index
        @returns operand type
        */
        static uint CollectInsn(cs_insn* insn, struct Section *sections, uint index);
        /**
        Decompiles Target Data
        @param data pointer to data
        @param data_size size of data
        @param offset include section offset
        @param index the section index
        */
        void Decompile(void* data, size_t data_size, size_t offset, uint index);
        //void Seek(uint64_t address, size_t data_size, uint index);
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
        static bool IsEndInsn(cs_insn *insn);
        static bool IsConditionalInsn(cs_insn *insn);
        /**
        Allocate Traits
        @param count number of traits to allocate
        @param index the section index
        @return bool
        */
        bool AllocTraits(uint count, uint index);
        /**
        Checks if Address if Function
        @param address address to check
        @return bool
        */
        static bool IsFunction(map<uint64_t, uint> &addresses, uint64_t address);
        /**
        Checks if Address if Function
        @param address address to check
        @return bool
        */
        static bool IsBlock(map<uint64_t, uint> &addresses, uint64_t address);
        /**
        Checks if Address was Already Visited
        @param address address to check
        @return bool
        */
        static bool IsVisited(map<uint64_t, int> &visited, uint64_t address);
        /**
        Check if Function or Block Address Collected
        @param address the address to check
        @return bool
        */
        bool IsAddress(map<uint64_t, uint> &addresses, uint64_t address, uint index);
        //void Seek(uint offset, uint index);
        ~DecompilerREV();

    };
}
#endif
