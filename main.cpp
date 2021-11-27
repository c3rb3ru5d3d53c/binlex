#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <iostream>
#include <string>
#include <algorithm>
#include "src/elf.h"
#include "src/pe.h"
#include "src/raw.h"
#include "src/macho.h"
#include "src/decompiler.h"
#include "src/decompiler_rev.h"
#include "src/args.h"
#include "src/cil.h"
#include "src/json.h"

using json = nlohmann::json;
using namespace std;

int main(int argc, char **argv){
    Args args;
    args.parse(argc, argv);
    if (strcmp(args.options.mode, (char *)"elf:x86_64") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Elf elf64;

        if (elf64.Setup(ELF_MODE_X86_64) == false){
            return 1;
        }
        if (elf64.ReadFile(args.options.input) == false){
            return 1;
        }
        if (elf64.GetExecutableData() == false){
            return 1;
        }
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64);
        for (int i = 0; i < ELF_MAX_SECTIONS; i++){
            if (elf64.sections[i].data != NULL){
                decompiler.x86_64(elf64.sections[i].data, elf64.sections[i].size, elf64.sections[i].offset, i);
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
        int result = false;
        Elf elf32;
        if (elf32.Setup(ELF_MODE_X86) == false){
            return 1;
        }
        if (elf32.ReadFile(args.options.input) == false){
            return 1;
        }
        if (elf32.GetExecutableData() == false){
            return 1;
        }
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32);
        for (int i = 0; i < ELF_MAX_SECTIONS; i++){
            if (elf32.sections[i].data != NULL){
                decompiler.x86_64(elf32.sections[i].data, elf32.sections[i].size, elf32.sections[i].offset, i);
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
        int result = false;
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
        int result = false;
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
        DecompilerREV decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32);
        decompiler.Decompile(rawx86.sections[0].data, rawx86.sections[0].size, rawx86.sections[0].offset, 0);
        // if (args.options.output == NULL){
        //     decompiler.PrintTraits(args.options.pretty);
        // } else {
        //     decompiler.WriteTraits(args.options.output, args.options.pretty);
        // }
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
        Raw raw_cil;
        if (raw_cil.ReadFile(args.options.input, 0) == false){
            return 1;
        }
        CILDecompiler cil_decompiler;
        if (cil_decompiler.Setup(CIL_DECOMPILER_TYPE_BLCKS) == false){
            return 1;
        }
        if (cil_decompiler.Decompile(raw_cil.sections[0].data, raw_cil.sections[0].size, 0) == false){
            return 1;
        }
        if (cil_decompiler.Setup(CIL_DECOMPILER_TYPE_FUNCS) == false){
            return 1;
        }
        if (cil_decompiler.Decompile(raw_cil.sections[0].data, raw_cil.sections[0].size, 0) == false){
            return 1;
        }
        if (args.options.output == NULL){
            cil_decompiler.PrintTraits();
        } else {
            cil_decompiler.WriteTraits(args.options.output);
        }
        return 0;
    }
    args.print_help();
    return 0;
}
