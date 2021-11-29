#include <string.h>
#include <capstone/capstone.h>
#include "args.h"
#include "decompiler.h"
#include "raw.h"
#include "pe.h"
#include "blelf.h"
#include "common.h"

using namespace binlex;

int main(int argc, char **argv){
    Args args;
    Common common;
    args.parse(argc, argv);
    if (args.options.mode == NULL){
        args.print_help();
        return 1;
    }
    if (strcmp(args.options.mode, (char *)"elf:x86_64") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Elf elfx86_64;
        if (elfx86_64.Setup(ELF_MODE_X86_64) == false){
            return 1;
        }
        if (elfx86_64.ReadFile(args.options.input) == false){
            return 1;
        }
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64);
        for (int i = 0; i < ELF_MAX_SECTIONS; i++){
            if (elfx86_64.sections[i].data != NULL){
                decompiler.x86_64(elfx86_64.sections[i].data, elfx86_64.sections[i].size, elfx86_64.sections[i].offset, i);
            }
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"elf:x86") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Elf elfx86;
        if (elfx86.Setup(ELF_MODE_X86) == false){
            return 1;
        }
        if (elfx86.ReadFile(args.options.input) == false){
            return 1;
        }
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32);
        for (int i = 0; i < ELF_MAX_SECTIONS; i++){
            if (elfx86.sections[i].data != NULL){
                decompiler.x86_64(elfx86.sections[i].data, elfx86.sections[i].size, elfx86.sections[i].offset, i);
            }
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"pe:x86") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Pe pe32;
        if (pe32.Setup(PE_MODE_X86) == false){
            return 1;
        }
        if (pe32.ReadFile(args.options.input) == false){
            return 1;
        }
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32);
        for (int i = 0; i < PE_MAX_SECTIONS; i++){
            if (pe32.sections[i].data != NULL){
                decompiler.x86_64(pe32.sections[i].data, pe32.sections[i].size, pe32.sections[i].offset, i);
            }
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"pe:x86_64") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Pe pe64;
        if (pe64.Setup(PE_MODE_X86_64) == false){
            return 1;
        }
        if (pe64.ReadFile(args.options.input) == false){
            return 1;
        }
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64);
        for (int i = 0; i < PE_MAX_SECTIONS; i++){
            if (pe64.sections[i].data != NULL){
                decompiler.x86_64(pe64.sections[i].data, pe64.sections[i].size, pe64.sections[i].offset, i);
            }
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"raw:x86") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Raw rawx86;
        rawx86.ReadFile(args.options.input, 0);
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32);
        decompiler.x86_64(rawx86.sections[0].data, rawx86.sections[0].size, rawx86.sections[0].offset, 0);
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"raw:x86_64") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Raw rawx86_64;
        rawx86_64.ReadFile(args.options.input, 0);
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64);
        decompiler.x86_64(rawx86_64.sections[0].data, rawx86_64.sections[0].size, rawx86_64.sections[0].offset, 0);
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"raw:cil") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        return 0;
    }
    args.print_help();
    return 0;
}
