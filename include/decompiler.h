#include <vector>
#include <queue>
#include <set>
#include <capstone/capstone.h>
#include "common.h"
#include "json.h"

#ifndef DECOMPILER_H
#define DECOMPILER_H

#define DECOMPILER_MAX_SECTIONS 256

#define DECOMPILER_OPERAND_TYPE_BLOCK    0
#define DECOMPILER_OPERAND_TYPE_FUNCTION 1
#define DECOMPILER_OPERAND_TYPE_UNSET    2

#define DECOMPILER_VISITED_QUEUED   0
#define DECOMPILER_VISITED_ANALYZED 1

#define DECOMPILER_GPU_MODE_CUDA   0
#define DECOMPILER_GPU_MODE_OPENCL 1

using namespace std;
using json = nlohmann::json;

namespace binlex {
    class Decompiler : public Common {
    private:
        typedef struct worker {
            csh handle;
            cs_err error;
            uint64_t pc;
            const uint8_t *code;
            size_t code_size;
        } worker;
        typedef struct{
            uint index;
            void *sections;
        } worker_args;
    public:
        struct Trait {
            char *corpus;
            char *type;
            char *architecture;
            string tmp_bytes;
            char *bytes;
            string tmp_trait;
            char *trait;
            uint edges;
            uint blocks;
            uint instructions;
            uint size;
            uint offset;
            uint invalid_instructions;
            uint cyclomatic_complexity;
            uint average_instructions_per_block;
            float bytes_entropy;
            float trait_entropy;
            char *trait_sha256;
            char *bytes_sha256;
        };
        struct Section {
            cs_arch arch;
            cs_mode mode;
            char *arch_str;
            char *cpu;
            char *corpus;
            uint threads;
            bool instructions;
            uint thread_cycles;
            useconds_t thread_sleep;
            uint offset;
            struct Trait **traits;
            uint ntraits;
            void *data;
            size_t data_size;
            set<uint64_t> coverage;
            map<uint64_t, uint> addresses;
            map<uint64_t, int> visited;
            queue<uint64_t> discovered;
        };
        struct Section sections[DECOMPILER_MAX_SECTIONS];
        Decompiler();
        /**
        Set up Capstone Decompiler Architecure and Mode
        @param arch Capstone Decompiler Architecure
        @param cs_mode Capstone Mode
        @param threads Number of Threads
        @param thread_cycles Thread Retry Cycle Cound
        @param thread_sleep Thread Sleep Wait for Queue in Microseconds
        @param index section index
        @return bool
        */
        bool Setup(cs_arch arch, cs_mode mode, bool instructions, char *corpus, uint threads, uint thread_cycles, useconds_t thread_sleep, uint index);
        /**
        Decompiler Thread Worker
        @param args pointer to worker arguments
        @returns NULL
        */
        static void * DecompileWorker(void *args);
        /**
        Collect Function and Conditional Operands for Processing
        @param insn the instruction
        @param operand_type the operand type
        @param index the section index
        @return bool
        */
        static void CollectOperands(cs_insn* insn, int operand_type, struct Section *sections, uint index);
        /**
        Collect Instructions for Processing
        @param insn the instruction
        @param index the section index
        @return operand type
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
        Append Additional Traits
        @param trait trait to append
        @param sections sections pointer
        @param index the section index
        @return bool
        */
        static void AppendTrait(struct Trait *trait, struct Section *sections, uint index);
        void FreeTraits(uint index);
        /**
        Checks if the Instruction is an Ending Instruction
        @param insn the instruction
        @return bool
        */
        static bool IsEndInsn(cs_insn *insn);
        /**
        Checks if Instruction is Conditional
        @param insn the instruction
        @return edges if > 0; then is conditional
        */
        static uint IsConditionalInsn(cs_insn *insn);
        /**
        Checks Code Coverage for Max Address
        @param coverage set of addresses decompiled
        @return the maximum address from the set
        */
        static uint64_t MaxAddress(set<uint64_t> coverage);
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
        /**
        Checks if Instruction is Wildcard Instruction
        @param insn the instruction
        @return bool
        */
        static bool IsWildcardInsn(cs_insn *insn);
        /**
        Wildcard Instruction
        @param insn the instruction
        @return trait wildcard byte string
        */
        static string WildcardInsn(cs_insn *insn);
        /**
        Clear Trait Values Except Type
        @param trait the trait struct address
        */
        static void ClearTrait(struct Trait *trait);
        /**
        Gets Trait as JSON
        @param trait pointer to trait structure
        @param pretty pretty print
        @return json string
        */
        static string GetTrait(struct Trait *trait, bool pretty);
        /**
        @param pretty pretty print traits
        */
        void PrintTraits(bool pretty);
        /**
        Write Traits to File
        @param file_path path to the file
        @param pretty pretty print traits
        */
        void WriteTraits(char *file_path, bool pretty);
        static void * TraitWorker(void *args);
        void AppendQueue(set<uint64_t> &addresses, uint operand_type, uint index);
        //void Seek(uint offset, uint index);
        ~Decompiler();

    };
}
#endif
