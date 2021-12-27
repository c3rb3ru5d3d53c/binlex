#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/time.h>
#include <signal.h>
#elif _WIN32
#include <windows.h>
#endif
#include "args.h"
#include "raw.h"
#include "pe.h"
#include "pe_rev.h"
#include "decompiler.h"
#include "blelf.h"

using namespace binlex;

void timeout_handler(int signum) {
    fprintf(stderr, "[x] execution timeout\n");
    exit(0);
}

#if defined(__linux__) || defined(__APPLE__)
void start_timeout(time_t seconds){
    struct itimerval timer;
    timer.it_value.tv_sec = seconds;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer (ITIMER_VIRTUAL, &timer, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = &timeout_handler;
    sigaction(SIGVTALRM, &sa, 0);
}
#endif

int main(int argc, char **argv){
    Args args;
    args.parse(argc, argv);
    if (args.options.timeout > 0){
        #if defined(__linux__) || defined(__APPLE__)
        start_timeout(args.options.timeout);
        #endif
    }
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
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64, args.options.instructions, args.options.corpus, args.options.threads, args.options.thread_cycles, args.options.thread_sleep, 0);
        for (int i = 0; i < ELF_MAX_SECTIONS; i++){
            if (elfx86_64.sections[i].data != NULL){
                decompiler.Decompile(elfx86_64.sections[i].data, elfx86_64.sections[i].size, elfx86_64.sections[i].offset, i);
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
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32, args.options.instructions, args.options.corpus, args.options.threads, args.options.thread_cycles, args.options.thread_sleep, 0);
        for (int i = 0; i < ELF_MAX_SECTIONS; i++){
            if (elfx86.sections[i].data != NULL){
                decompiler.Decompile(elfx86.sections[i].data, elfx86.sections[i].size, elfx86.sections[i].offset, i);
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
        PEREV pe32;
        pe32.ReadFile(args.options.input);
        // Pe pe32;
        // if (pe32.Setup(PE_MODE_X86) == false){
        //     return 1;
        // }
        // if (pe32.ReadFile(args.options.input) == false){
        //     return 1;
        // }
        // Decompiler decompiler;
        // decompiler.Setup(CS_ARCH_X86, CS_MODE_32, args.options.instructions, args.options.corpus, args.options.threads, args.options.thread_cycles, args.options.thread_sleep, 0);
        // for (int i = 0; i < PE_MAX_SECTIONS; i++){
        //     if (pe32.sections[i].data != NULL){
        //         decompiler.Decompile(pe32.sections[i].data, pe32.sections[i].size, pe32.sections[i].offset, i);
        //     }
        // }
        // if (args.options.output == NULL){
        //     decompiler.PrintTraits(args.options.pretty);
        // } else {
        //     decompiler.WriteTraits(args.options.output, args.options.pretty);
        // }
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
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64, args.options.instructions, args.options.corpus, args.options.threads, args.options.thread_cycles, args.options.thread_sleep, 0);
        for (int i = 0; i < PE_MAX_SECTIONS; i++){
            if (pe64.sections[i].data != NULL){
                decompiler.Decompile(pe64.sections[i].data, pe64.sections[i].size, pe64.sections[i].offset, i);
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
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32, args.options.instructions, args.options.corpus, args.options.threads, args.options.thread_cycles, args.options.thread_sleep, 0);
        decompiler.Decompile(rawx86.sections[0].data, rawx86.sections[0].size, rawx86.sections[0].offset, 0);
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
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64, args.options.instructions, args.options.corpus, args.options.threads, args.options.thread_cycles, args.options.thread_sleep, 0);
        decompiler.Decompile(rawx86_64.sections[0].data, rawx86_64.sections[0].size, rawx86_64.sections[0].offset, 0);
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"raw:cil") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        printf("comming soon...\n");
        return 0;
    }
    args.print_help();
    return 0;
}
