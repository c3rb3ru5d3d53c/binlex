#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/time.h>
#include <signal.h>
#elif _WIN32
#include <windows.h>
#endif
#include "common.h"
#include "args.h"
#include "raw.h"
#include "pe.h"
#include "cil.h"
#include "pe-dotnet.h"
#include "blelf.h"
#include "decompiler.h"

#ifdef _WIN32
#pragma comment(lib, "capstone")
#pragma comment(lib, "binlex")
#endif
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
        return EXIT_FAILURE;
    }
    if (strcmp(args.options.mode, (char *)"elf:x86_64") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        ELF elf64;
        if (elf64.Setup(ARCH::EM_X86_64) == false){
            return EXIT_FAILURE;
        }
        if (elf64.ReadFile(args.options.input) == false){
            return EXIT_FAILURE;
        }
        Decompiler decompiler;
        for (int i = 0; i < elf64.total_exec_sections; i++){
            decompiler.Setup(CS_ARCH_X86, CS_MODE_64, i);
            decompiler.SetThreads(args.options.threads, args.options.thread_cycles, args.options.thread_sleep, i);
            decompiler.SetCorpus(args.options.corpus, i);
            decompiler.SetInstructions(args.options.instructions, i);
            decompiler.AppendQueue(elf64.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
            decompiler.Decompile(elf64.sections[i].data, elf64.sections[i].size, elf64.sections[i].offset, i);
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return EXIT_SUCCESS;
    }
    if (strcmp(args.options.mode, (char *)"elf:x86") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        ELF elf32;
        if (elf32.Setup(ARCH::EM_386) == false){
            return EXIT_FAILURE;
        }
        if (elf32.ReadFile(args.options.input) == false){
            return EXIT_FAILURE;
        }
        Decompiler decompiler;
        for (int i = 0; i < elf32.total_exec_sections; i++){
            decompiler.Setup(CS_ARCH_X86, CS_MODE_32, i);
            decompiler.SetThreads(args.options.threads, args.options.thread_cycles, args.options.thread_sleep, i);
            decompiler.SetCorpus(args.options.corpus, i);
            decompiler.SetInstructions(args.options.instructions, i);
            decompiler.AppendQueue(elf32.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
            decompiler.Decompile(elf32.sections[i].data, elf32.sections[i].size, elf32.sections[i].offset, i);
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return EXIT_SUCCESS;
    }
    if (strcmp(args.options.mode, (char *)"pe:cil") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        // TODO: This should be valid for both x86-86 and x86-64
        // we need to do this more generic
        DOTNET pe;
        if (pe.Setup(MACHINE_TYPES::IMAGE_FILE_MACHINE_I386) == false) return 1;
        if (pe.ReadFile(args.options.input) == false) return 1;

        for (size_t i = 0; i < pe._sections.size(); i++) {
            if (pe._sections[i].offset == 0) continue;
		    CILDecompiler cil_decompiler;

            if (cil_decompiler.Setup(CIL_DECOMPILER_TYPE_FUNCS) == false){
                return 1;
            }
			if (cil_decompiler.Decompile(pe._sections[i].data, pe._sections[i].size, 0) == false){
                continue;
			}
		    if (args.options.output == NULL){
		    	cil_decompiler.PrintTraits();
		    } else {
		    	cil_decompiler.WriteTraits(args.options.output);
		    }
        }
        return 0;
    }
    if (strcmp(args.options.mode, (char *)"pe:x86") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        PE pe32;
        if (pe32.Setup(MACHINE_TYPES::IMAGE_FILE_MACHINE_I386) == false){
            return EXIT_FAILURE;
        }
        if (pe32.ReadFile(args.options.input) == false){
            return EXIT_FAILURE;
        }
        Decompiler decompiler;
        for (int i = 0; i < pe32.total_exec_sections; i++){
            decompiler.Setup(CS_ARCH_X86, CS_MODE_32, i);
            decompiler.SetThreads(args.options.threads, args.options.thread_cycles, args.options.thread_sleep, i);
            decompiler.SetCorpus(args.options.corpus, i);
            decompiler.SetInstructions(args.options.instructions, i);
            decompiler.AppendQueue(pe32.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
            decompiler.Decompile(pe32.sections[i].data, pe32.sections[i].size, pe32.sections[i].offset, i);
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return EXIT_SUCCESS;
    }
    if (strcmp(args.options.mode, (char *)"pe:x86_64") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        PE pe64;
        if (pe64.Setup(MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64) == false){
            return EXIT_FAILURE;
        }
        if (pe64.ReadFile(args.options.input) == false){
            return EXIT_FAILURE;
        }
        Decompiler decompiler;
        for (int i = 0; i < pe64.total_exec_sections; i++){
            decompiler.Setup(CS_ARCH_X86, CS_MODE_64, i);
            decompiler.SetThreads(args.options.threads, args.options.thread_cycles, args.options.thread_sleep, i);
            decompiler.SetCorpus(args.options.corpus, i);
            decompiler.SetInstructions(args.options.instructions, i);
            decompiler.AppendQueue(pe64.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
            decompiler.Decompile(pe64.sections[i].data, pe64.sections[i].size, pe64.sections[i].offset, i);
        }
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return EXIT_SUCCESS;
    }
    if (strcmp(args.options.mode, (char *)"raw:x86") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Raw rawx86;
        if (rawx86.ReadFile(args.options.input, 0) == false)
        {
            return EXIT_FAILURE;
        }
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32, 0);
        decompiler.SetThreads(args.options.threads, args.options.thread_cycles, args.options.thread_sleep, 0);
        decompiler.SetCorpus(args.options.corpus, 0);
        decompiler.SetInstructions(args.options.instructions, 0);
        decompiler.Decompile(rawx86.sections[0].data, rawx86.sections[0].size, rawx86.sections[0].offset, 0);
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return EXIT_SUCCESS;
    }
    if (strcmp(args.options.mode, (char *)"raw:x86_64") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        Raw rawx86_64;
        if (rawx86_64.ReadFile(args.options.input, 0) == false)
        {
            return EXIT_FAILURE;
        }
        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64, 0);
        decompiler.SetThreads(args.options.threads, args.options.thread_cycles, args.options.thread_sleep, 0);
        decompiler.SetCorpus(args.options.corpus, 0);
        decompiler.SetInstructions(args.options.instructions, 0);
        decompiler.Decompile(rawx86_64.sections[0].data, rawx86_64.sections[0].size, rawx86_64.sections[0].offset, 0);
        if (args.options.output == NULL){
            decompiler.PrintTraits(args.options.pretty);
        } else {
            decompiler.WriteTraits(args.options.output, args.options.pretty);
        }
        return EXIT_SUCCESS;
    }
    if (strcmp(args.options.mode, (char *)"raw:cil") == 0 &&
        args.options.io_type == ARGS_IO_TYPE_FILE){
        printf("comming soon...\n");
        return EXIT_FAILURE;
    }

    args.print_help();
    return EXIT_FAILURE;
}
