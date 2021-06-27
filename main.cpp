#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include "src/elf.h"
#include "src/pe.h"
#include "src/decompiler.h"
#include "src/args.h"

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
                decompiler.x86_64(DECOMPILER_TYPE_FUNCS, elf64.sections[i].data, elf64.sections[i].size, i);
                decompiler.x86_64(DECOMPILER_TYPE_BLCKS, elf64.sections[i].data, elf64.sections[i].size, i);
            }
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(DECOMPILER_TYPE_ALL);
        } else {
            decompiler.WriteTraits(DECOMPILER_TYPE_ALL, args.options.output);
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
                decompiler.x86_64(DECOMPILER_TYPE_FUNCS, elf32.sections[i].data, elf32.sections[i].size, i);
                decompiler.x86_64(DECOMPILER_TYPE_BLCKS, elf32.sections[i].data, elf32.sections[i].size, i);
            }
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(DECOMPILER_TYPE_ALL);
        } else {
            decompiler.WriteTraits(DECOMPILER_TYPE_ALL, args.options.output);
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
                //common_hex_dump((char *)"section", pe32.sections[i].data, pe32.sections[i].size);
                decompiler.x86_64(DECOMPILER_TYPE_FUNCS, pe32.sections[i].data, pe32.sections[i].size, i);
                decompiler.x86_64(DECOMPILER_TYPE_BLCKS, pe32.sections[i].data, pe32.sections[i].size, i);
            }
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(DECOMPILER_TYPE_ALL);
        } else {
            decompiler.WriteTraits(DECOMPILER_TYPE_ALL, args.options.output);
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
                common_hex_dump((char *)"section", pe64.sections[i].data, pe64.sections[i].size);
                //decompiler.x86_64(DECOMPILER_TYPE_FUNCS, pe64.sections[i].data, pe64.sections[i].size, i);
                //decompiler.x86_64(DECOMPILER_TYPE_BLCKS, pe64.sections[i].data, pe64.sections[i].size, i);
            }
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(DECOMPILER_TYPE_ALL);
        } else {
            decompiler.WriteTraits(DECOMPILER_TYPE_ALL, args.options.output);
        }
        return 0;
    }
    args.print_help();
    return 0;
}
