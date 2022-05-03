#ifdef _WIN32
#include <Windows.h>
#endif
#include <iostream>
#include <fstream>
#include <memory>
#include <iostream>
#include <exception>
#include <stdexcept>
#include "auto.h"
#include "pe.h"
#include "blelf.h"
#include "decompiler.h"
#include <LIEF/LIEF.hpp>
#include <LIEF/PE.hpp>

using namespace std;
using namespace binlex;

AutoLex::AutoLex(){
    characteristics.mode = CS_MODE_32;
    characteristics.format = LIEF::FORMAT_PE;
    characteristics.arch = CS_ARCH_X86;
    characteristics.machineType = (int) MACHINE_TYPES::IMAGE_FILE_MACHINE_I386;
}

bool AutoLex::HasLimitations(char *file_path){

    //Check that we can pull the file characteristics
    if (!GetFileCharacteristics(file_path)){
        return true;
    }

    if(characteristics.format == LIEF::FORMAT_ELF) {
        switch((ARCH)characteristics.machineType) {
            case ARCH::EM_386:
                return false;
            case ARCH::EM_X86_64:
                return false;
            default:
                return true;
        }
    }

    if(characteristics.format != LIEF::FORMAT_PE){
        //unsupported format
        return true;
    }

    // If anything other than x64 32/64 return true
    switch((MACHINE_TYPES)characteristics.machineType){
        case MACHINE_TYPES::IMAGE_FILE_MACHINE_I386:
            break;
        case MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64:
            break;
        default:
            return true;
    }

    auto bin = LIEF::PE::Parser::parse(file_path);
    if(bin->has_imports()){
        auto imports = bin->imports();
        for(Import i : imports){
            if(i.name() == "MSVBVM60.DLL"){
                return true;
            }
        }
    }
    return false;
}

bool AutoLex::IsDotNet(char *file_path){
    try {
        auto bin = LIEF::PE::Parser::parse(file_path);
        auto imports = bin->imports();

        for(Import i : imports)
        {
            if (i.name() == "mscorelib.dll") {
                if(bin->data_directory(DATA_DIRECTORY::CLR_RUNTIME_HEADER).RVA() > 0) {
                    return true;
                }
            }
            if (i.name() == "mscoree.dll") {
                if(bin->data_directory(DATA_DIRECTORY::CLR_RUNTIME_HEADER).RVA() > 0) {
                    return true;
                }
            }
        }
        return false;
    }
    catch(LIEF::bad_format bf){
        return false;
    }
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

Decompiler AutoLex::ProcessFile(char *file_path, uint threads, uint timeout, uint thread_cycles, useconds_t thread_sleep, bool instructions){

    // Todo:
    // - raise exceptions instead of returning a null decompiler  to better handle being called as a lib

    Decompiler decompiler;

    if (!GetFileCharacteristics(file_path)){
        fprintf(stderr, "Unable to get file characteristics.\n");
        return decompiler;
    }

    if(characteristics.format == LIEF::FORMAT_PE){

        if(IsDotNet(file_path)){
            fprintf(stderr, "CIL Decompiler not implemented.\n");
            return decompiler;
        }

        PE pe32;
        if (!pe32.Setup((MACHINE_TYPES)characteristics.machineType)){
            return decompiler;
        }

        if (!pe32.ReadFile(file_path)){
            return decompiler;
        }

        for (int i = 0; i < BINARY_MAX_SECTIONS; i++) {
            if (pe32.sections[i].data != NULL) {
                decompiler.Setup(characteristics.arch, characteristics.mode, i);
                decompiler.AppendQueue(pe32.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
                decompiler.Decompile(pe32.sections[i].data, pe32.sections[i].size, pe32.sections[i].offset, i);
            }
        }
    }
    else if(characteristics.format == LIEF::FORMAT_ELF){
        ELF elf;

        if (elf.Setup((ARCH)characteristics.machineType) == false){
            return decompiler;
        }
        if (!elf.ReadFile(file_path)){
            return decompiler;
        }

        for (int i = 0; i < BINARY_MAX_SECTIONS; i++){
            if (elf.sections[i].data != NULL){
                decompiler.Setup(characteristics.arch, characteristics.mode, i);
                decompiler.AppendQueue(elf.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
                decompiler.Decompile(elf.sections[i].data, elf.sections[i].size, elf.sections[i].offset, i);
            }
        }
    }

    return decompiler;
}
