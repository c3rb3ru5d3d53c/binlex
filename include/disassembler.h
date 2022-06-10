#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <iomanip>
#include <math.h>
#include <capstone/capstone.h>
#include "common.h"
#include "json.h"
#include "file.h"
#include "disassemblerbase.h"

#if defined(__linux__) || defined(__APPLE__)
#include <pthread.h>
#include <unistd.h>
#elif _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif

#define SHA256_PRINTABLE_SIZE   65 /* including NULL terminator */

typedef enum DISASSEMBLER_VISITED {
    DISASSEMBLER_VISITED_QUEUED = 0,
    DISASSEMBLER_VISITED_ANALYZED = 1
} DISASSEMBLER_VISITED;

typedef enum DISASSEMBLER_OPERAND_TYPE {
	DISASSEMBLER_OPERAND_TYPE_BLOCK = 0,
	DISASSEMBLER_OPERAND_TYPE_FUNCTION = 1,
	DISASSEMBLER_OPERAND_TYPE_UNSET = 2
} DISASSEMBLER_OPERAND_TYPE;

using json = nlohmann::json;

namespace binlex {
    class Disassembler : public DisassemblerBase{
    private:
        typedef struct disasm_t {
            csh handle;
            cs_err error;
            uint64_t pc;
            const uint8_t *code;
            size_t code_size;
        } disasm_t;
    public:
        struct Trait {
            string type;
            string bytes;
            string trait;
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
            string bytes_sha256;
            string trait_sha256;
            set<uint64_t> xrefs;
        };
        struct Section {
            char *cpu;
            bool instructions;
            uint offset;
            vector<struct Trait> traits;
            void *data;
            size_t data_size;
            set<uint64_t> blocks;
            set<uint64_t> functions;
            map<uint64_t, DISASSEMBLER_VISITED> visited;
            queue<uint64_t> discovered;
        };
        static cs_arch arch;
        static cs_mode mode;
        struct Section sections[BINARY_MAX_SECTIONS];
        BINLEX_EXPORT Disassembler(const binlex::File &firef);
        /**
         * This method processes the queue and collects traits for a section.
         * @param args pointer to worker arguments
         * @returns NULL
         */
        BINLEX_EXPORT void* CreateTraitsForSection(uint index);
        /**
         * This method adds a discovered block address to queue.
         * @param address the block address
         * @param operand_type the operand type
         * @param index the section index
         * @return bool
         */
        BINLEX_EXPORT static void AddDiscoveredBlock(uint64_t address, struct Section *sections, uint index);
        /**
         * This method adds a discovered function address to queue.
         * @param address the block address
         * @param operand_type the operand type
         * @param index the section index
         * @return bool
         */
        BINLEX_EXPORT static void AddDiscoveredFunction(uint64_t address, struct Section *sections, uint index);
        /**
         * This method collects addresses.
         * @param insn the instruction
         * @param operand_type the operand type
         * @param index the section index
         * @return bool
         */
        BINLEX_EXPORT static void CollectOperands(cs_insn* insn, int operand_type, struct Section *sections, uint index);
        /**
         * This method collects addresses from instructions and adds them to the queue.
         * @param insn the instruction
         * @param index the section index
         * @return operand type
         */
        BINLEX_EXPORT DISASSEMBLER_OPERAND_TYPE CollectInsn(cs_insn* insn, struct Section *sections, uint index);
        /**
         * This method performs a linear disassembly of the binary to identify initial blocks and functions for the queue.
         * @param data pointer to data
         * @param data_size size of data
         * @param offset include section offset
         * @param index the section index
         */
        BINLEX_EXPORT void LinearDisassemble(void* data, size_t data_size, size_t offset, uint index);
        /**
         * This method disassembles the binary and collects traits.
         * @param data pointer to data
         * @param data_size size of data
         * @param offset include section offset
         * @param index the section index
         */
        BINLEX_EXPORT void Disassemble();
        /**
         * This method appends traits to the section.
         * @param trait trait to append
         * @param sections sections pointer
         * @param index the section index
         * @return bool
         */
        BINLEX_EXPORT static void AppendTrait(struct Trait *trait, struct Section *sections, uint index);
        /**
         * This method checks if the instruction is a nop instruction.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsNopInsn(cs_insn *ins);
        /**
         * Checks if the Instruction is a semantic nop (padding)
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsSemanticNopInsn(cs_insn *ins);
        /**
         * This method checks if the instruction is a trap instruction.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsTrapInsn(cs_insn *ins);
        /**
         * This method checks if the instruction is privileged.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsPrivInsn(cs_insn *ins);
        /**
         * This method checks if the instruction is a return instruction.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsRetInsn(cs_insn *insn);
        /**
         * This method if instruction is an unconditional jump.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsUnconditionalJumpInsn(cs_insn *insn);
        /**
         * This method checks if an instruction is suspicious.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT bool IsSuspiciousInsn(cs_insn *insn);
        /**
         * This method checks if the instruction is a conditional jump.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsConditionalJumpInsn(cs_insn *insn);
        /**
         * This method checks if the instruction is a jump instruction.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsJumpInsn(cs_insn *insn);
        /**
         * This method checks if the instruction  is a call instruction.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsCallInsn(cs_insn *insn);
        /**
         * This method checks if the instruction is a padding instruction.
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT bool IsPaddingInsn(cs_insn *ins);
        /**
         * This method returns how many edges an instruction has.
         * @param insn
         * @return bool
         */
        BINLEX_EXPORT static uint64_t GetInsnEdges(cs_insn *insn);
        /**
         * This method checks if the address is a function.
         * @param address address to check
         * @return bool
         */
        BINLEX_EXPORT static bool IsFunction(set<uint64_t> &addresses, uint64_t address);
        /**
         * This method check sif the address is a block.
         * @param address address to check
         * @return bool
         */
        BINLEX_EXPORT static bool IsBlock(set<uint64_t> &addresses, uint64_t address);
        /**
         * This method checks if the address was already visited by the disassembler.
         * @param address address to check
         * @return bool
         */
        BINLEX_EXPORT static bool IsVisited(map<uint64_t, DISASSEMBLER_VISITED> &visited, uint64_t address);
        /**
         * Checks if Instruction is Wildcard Instruction
         * @param insn the instruction
         * @return bool
         */
        BINLEX_EXPORT static bool IsWildcardInsn(cs_insn *insn);
        /**
         * This method performs wildcarding on an instruction.
         * @param insn the instruction
         * @return trait wildcard string
         */
        BINLEX_EXPORT static string WildcardInsn(cs_insn *insn);
        /**
         * This method clears all properties about a trait except its type.
         * @param trait the trait struct address
         */
        BINLEX_EXPORT static void ClearTrait(struct Trait *trait);
        /**
         * Gets Trait as JSON
         * @param trait pointer to trait structure
         * @return json string
         */
        BINLEX_EXPORT json GetTrait(struct Trait &trait);
        /**
         * This method returns a trait as json.
         * @return json
         */
        vector<json> GetTraits();
        /**
         * This method performs post-proceessing on a trait.
         * @param trait pointer to the trait to perform post-processing on
         */
	    BINLEX_EXPORT static void * FinalizeTrait(struct Trait &trait);
        /**
         * This method appends the queue with a set of functions or blocks.
         * @param addresses a set of addresses
         * @param operand_type the type of operand
         * @param index the section index
         */
        BINLEX_EXPORT void AppendQueue(set<uint64_t> &addresses, DISASSEMBLER_OPERAND_TYPE operand_type, uint index);
        BINLEX_EXPORT ~Disassembler();
    };
}
#endif
