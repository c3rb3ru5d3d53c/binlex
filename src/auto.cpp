#include "auto.h"

using namespace std;
using namespace binlex;

AutoLex::AutoLex(){
    characteristics.mode = CS_MODE_32;
    characteristics.format = LIEF::FORMAT_PE;
    characteristics.arch = CS_ARCH_X86;
    characteristics.machineType = (int) MACHINE_TYPES::IMAGE_FILE_MACHINE_I386;
}

bool AutoLex::GetFileCharacteristics(char * file_path){

    auto bin = LIEF::Parser::parse(file_path);

    characteristics.format = bin->format();

    if(bin->header().is_32()){
        characteristics.mode = CS_MODE_32;
        if(bin->format() == LIEF::FORMAT_PE) {
            characteristics.machineType = (int) MACHINE_TYPES::IMAGE_FILE_MACHINE_I386;
        }
        else if(bin->format() == LIEF::FORMAT_ELF) {
            characteristics.machineType = (int) ARCH::EM_386;
        }
    }
    else if(bin->header().is_64()){
        characteristics.mode = CS_MODE_64;
        if(bin->format() == LIEF::FORMAT_PE) {
            characteristics.machineType = (int) MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64;
        }
        else if(bin->format() == LIEF::FORMAT_ELF) {
            characteristics.machineType = (int) ARCH::EM_X86_64;
        }
    }
    return true;
}


int AutoLex::ProcessFile(char *file_path){

    // Todo:
    // - raise exceptions instead of returning a null decompiler  to better handle being called as a lib

    if (!GetFileCharacteristics(file_path)){
        fprintf(stderr, "[x] unable to get file characteristics\n");
        return -1;
    }

    if(characteristics.format == LIEF::FORMAT_PE){
        PE pe;
        Decompiler decompiler(pe);
        if (!pe.Setup((MACHINE_TYPES)characteristics.machineType)){
            return EXIT_FAILURE;
        }

        if (!pe.ReadFile(file_path)){
            return EXIT_FAILURE;
        }

        if(pe.HasLimitations()){
            PRINT_ERROR_AND_EXIT("[x] file has limitations\n");
        }

        if(pe.IsDotNet()){
            DOTNET pe;
            g_args.options.mode = "pe:cil";
            if (pe.Setup(MACHINE_TYPES::IMAGE_FILE_MACHINE_I386) == false) return 1;
            if (pe.ReadFile(file_path) == false) return 1;
            CILDecompiler cil_decompiler(pe);
            int si = 0;
            for (auto section : pe._sections) {
                if (section.offset == 0) continue;
                if (cil_decompiler.Setup(CIL_DECOMPILER_TYPE_ALL) == false) return 1;
                if (cil_decompiler.Decompile(section.data, section.size, si) == false) continue;
	            si++;
            }
            cil_decompiler.WriteTraits();
            return EXIT_SUCCESS;
        } else {
            if (characteristics.arch == CS_ARCH_X86 &&
                characteristics.mode == CS_MODE_32){
                g_args.options.mode = "pe:x86";

            }
            if (characteristics.arch == CS_ARCH_X86 &&
                characteristics.mode == CS_MODE_64){
                    g_args.options.mode = "pe:x86_64";
            }

            decompiler.Setup(characteristics.arch, characteristics.mode);
            for (int i = 0; i < pe.total_exec_sections; i++) {
                if (pe.sections[i].data != NULL) {
                    decompiler.AppendQueue(pe.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
                    decompiler.Decompile(pe.sections[i].data, pe.sections[i].size, pe.sections[i].offset, i);
                }
            }
            decompiler.WriteTraits();
        }
    }
    else if (characteristics.format == LIEF::FORMAT_ELF){
        ELF elf;
        Decompiler decompiler(elf);
        if (elf.Setup((ARCH)characteristics.machineType) == false){
            return EXIT_FAILURE;
        }
        if (!elf.ReadFile(file_path)){
            return EXIT_FAILURE;
        }

        if (characteristics.arch == CS_ARCH_X86 &&
            characteristics.mode == CS_MODE_32){
            g_args.options.mode = "elf:x86";

        }
        if (characteristics.arch == CS_ARCH_X86 &&
            characteristics.mode == CS_MODE_64){
                g_args.options.mode = "elf:x86_64";
        }

        decompiler.Setup(characteristics.arch, characteristics.mode);
        for (int i = 0; i < elf.total_exec_sections; i++){
            if (elf.sections[i].data != NULL){
                decompiler.AppendQueue(elf.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
                decompiler.Decompile(elf.sections[i].data, elf.sections[i].size, elf.sections[i].offset, i);
            }

        }
        decompiler.WriteTraits();
    }

    return EXIT_SUCCESS;
}
