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
#include "auto.h"
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
    g_args.parse(argc, argv);

    if (g_args.options.timeout > 0){
        #if defined(__linux__) || defined(__APPLE__)
        start_timeout(g_args.options.timeout);
        #endif
    }
    if (g_args.options.mode == NULL){
        g_args.print_help();
        return EXIT_FAILURE;
    }
    if (strcmp(g_args.options.mode, (char *)"auto") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        AutoLex autolex;
        return autolex.ProcessFile(g_args.options.input);
        return 0;
    }
    if (strcmp(g_args.options.mode, (char *)"elf:x86_64") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        ELF elf64;
        if (elf64.Setup(ARCH::EM_X86_64) == false){
            return EXIT_FAILURE;
        }
        if (elf64.ReadFile(g_args.options.input) == false){
            return EXIT_FAILURE;
        }
        PRINT_DEBUG("Number of total executable sections = %u\n", elf64.total_exec_sections);

        Decompiler decompiler;
        for (int i = 0; i < elf64.total_exec_sections; i++){
            decompiler.Setup(CS_ARCH_X86, CS_MODE_64, i);
            decompiler.AppendQueue(elf64.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
            decompiler.Decompile(elf64.sections[i].data, elf64.sections[i].size, elf64.sections[i].offset, i);
        }
        decompiler.WriteTraits();
        return EXIT_SUCCESS;
    }
    if (strcmp(g_args.options.mode, (char *)"elf:x86") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        ELF elf32;
        if (elf32.Setup(ARCH::EM_386) == false){
            return EXIT_FAILURE;
        }
        if (elf32.ReadFile(g_args.options.input) == false){
            return EXIT_FAILURE;
        }
        PRINT_DEBUG("Number of total executable sections = %u\n", elf32.total_exec_sections);

        Decompiler decompiler;
        for (int i = 0; i < elf32.total_exec_sections; i++){
            decompiler.Setup(CS_ARCH_X86, CS_MODE_32, i);
            decompiler.AppendQueue(elf32.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
            decompiler.Decompile(elf32.sections[i].data, elf32.sections[i].size, elf32.sections[i].offset, i);
        }
        decompiler.WriteTraits();
        return EXIT_SUCCESS;
    }
    if (strcmp(g_args.options.mode, (char *)"pe:cil") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        // TODO: This should be valid for both x86-86 and x86-64
        // we need to do this more generic
        DOTNET pe;
        if (pe.Setup(MACHINE_TYPES::IMAGE_FILE_MACHINE_I386) == false) return 1;
        if (pe.ReadFile(g_args.options.input) == false) return 1;

        CILDecompiler cil_decompiler;
        PRINT_DEBUG("Analyzing %lu sections for CIL byte code.\n", pe._sections.size());
        for (size_t i = 0; i < pe._sections.size(); i++) {
            if (pe._sections[i].offset == 0) continue;

            if (cil_decompiler.Setup(CIL_DECOMPILER_TYPE_BLCKS) == false){
                return 1;
            }
			if (cil_decompiler.Decompile(pe._sections[i].data, pe._sections[i].size, 0) == false){
                continue;
			}
        }
        if (g_args.options.output == NULL){
		    cil_decompiler.PrintTraits();
		} else {
		    cil_decompiler.WriteTraits(g_args.options.output);
		}
        return 0;
    }
    if (strcmp(g_args.options.mode, (char *)"pe:x86") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        PE pe32;
        if (pe32.Setup(MACHINE_TYPES::IMAGE_FILE_MACHINE_I386) == false){
            return EXIT_FAILURE;
        }
        if (pe32.ReadFile(g_args.options.input) == false){
            return EXIT_FAILURE;
        }
        PRINT_DEBUG("Number of total sections = %u\n", pe32.total_exec_sections);

        Decompiler decompiler;
        for (int i = 0; i < pe32.total_exec_sections; i++){
            decompiler.Setup(CS_ARCH_X86, CS_MODE_32, i);
            decompiler.AppendQueue(pe32.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
            decompiler.Decompile(pe32.sections[i].data, pe32.sections[i].size, pe32.sections[i].offset, i);
        }
        decompiler.WriteTraits();
        return EXIT_SUCCESS;
    }
    if (strcmp(g_args.options.mode, (char *)"pe:x86_64") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        PE pe64;
        if (pe64.Setup(MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64) == false){
            return EXIT_FAILURE;
        }
        if (pe64.ReadFile(g_args.options.input) == false){
            return EXIT_FAILURE;
        }
        PRINT_DEBUG("Number of total executable sections = %u\n", pe64.total_exec_sections);

        Decompiler decompiler;
        for (int i = 0; i < pe64.total_exec_sections; i++){
            decompiler.Setup(CS_ARCH_X86, CS_MODE_64, i);
            decompiler.AppendQueue(pe64.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
            decompiler.Decompile(pe64.sections[i].data, pe64.sections[i].size, pe64.sections[i].offset, i);
        }
        decompiler.WriteTraits();
        return EXIT_SUCCESS;
    }
    if (strcmp(g_args.options.mode, (char *)"raw:x86") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        Raw rawx86;
        if (rawx86.ReadFile(g_args.options.input, 0) == false)
        {
            return EXIT_FAILURE;
        }

        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_32, 0);
        decompiler.Decompile(rawx86.sections[0].data, rawx86.sections[0].size, rawx86.sections[0].offset, 0);
        decompiler.WriteTraits();
        return EXIT_SUCCESS;
    }
    if (strcmp(g_args.options.mode, (char *)"raw:x86_64") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        Raw rawx86_64;
        if (rawx86_64.ReadFile(g_args.options.input, 0) == false)
        {
            return EXIT_FAILURE;
        }

        Decompiler decompiler;
        decompiler.Setup(CS_ARCH_X86, CS_MODE_64, 0);
        decompiler.Decompile(rawx86_64.sections[0].data, rawx86_64.sections[0].size, rawx86_64.sections[0].offset, 0);
        decompiler.WriteTraits();
        return EXIT_SUCCESS;
    }
    if (strcmp(g_args.options.mode, (char *)"raw:cil") == 0 &&
        g_args.options.io_type == ARGS_IO_TYPE_FILE){
        printf("comming soon...\n");
        return EXIT_FAILURE;
    }

    g_args.print_help();
    return EXIT_FAILURE;
}
