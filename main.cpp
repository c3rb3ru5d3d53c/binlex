#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include "src/elf.h"
#include "src/decompiler.h"
#include "src/args.h"

int main(int argc, char **argv){
    Args args;
    args.parse(argc, argv);
    if (strcmp(args.options.mode, (char *)"elf:x86_64") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Elf64 elf64;
        elf64.ReadFile(args.options.input);
        elf64.GetSection((char *)".text");
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64);
        decompiler.decompiler_type = DECOMPILER_TYPE_FUNCS;
        decompiler.x86_64(elf64.s_data, elf64.s_size);
        decompiler.decompiler_type = DECOMPILER_TYPE_BLCKS;
        decompiler.x86_64(elf64.s_data, elf64.s_size);
        if (args.options.output == NULL){
            printf("%s", decompiler.traits);
        } else {
            decompiler.write_traits(args.options.output);
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"elf:x86") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Elf32 elf32;
        elf32.ReadFile(args.options.input);
        elf32.GetSection((char *)".text");
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32);
        decompiler.decompiler_type = DECOMPILER_TYPE_FUNCS;
        decompiler.x86_64(elf32.s_data, elf32.s_size);
        decompiler.decompiler_type = DECOMPILER_TYPE_BLCKS;
        decompiler.x86_64(elf32.s_data, elf32.s_size);
        if (args.options.output == NULL){
            printf("%s", decompiler.traits);
        } else {
            decompiler.write_traits(args.options.output);
        }
        return 0;
    }
    args.print_help();
    return 0;
}
