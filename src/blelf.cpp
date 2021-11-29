#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <assert.h>
#include <elf.h>
#include "blelf.h"

using namespace binlex;

Elf::Elf(){
    SetSectionsDefault();
}

void Elf::SetSectionsDefault(){
    for (int i = 0; i < ELF_MAX_SECTIONS; i++){
        sections[i].data = NULL;
        sections[i].offset = 0;
        sections[i].size = 0;
    }
}

bool Elf::is_arch(int arch){
    if (mode == ELF_MODE_X86){
        Elf32_Ehdr *header_local = (Elf32_Ehdr *)header;
        if (header_local->e_machine == arch){
            return true;
        }
    }
    if (mode == ELF_MODE_X86_64){
        Elf64_Ehdr *header_local = (Elf64_Ehdr *)header;
        if (header_local->e_machine == arch){
            return true;
        }
    }
    return false;
}

bool Elf::is_elf(){
    int result = 1;
    if (mode == ELF_MODE_X86){
        Elf32_Ehdr *header_local = (Elf32_Ehdr *)header;
        result =  memcmp(header_local->e_ident, magic, sizeof(magic));
    }
    if (mode == ELF_MODE_X86_64){
        Elf64_Ehdr *header_local = (Elf64_Ehdr *)header;
        result =  memcmp(header_local->e_ident, magic, sizeof(magic));
    }
    if (result == 1){
        return false;
    }
    return true;
}

unsigned int Elf::GetSectionTableSize(){
    if (mode == ELF_MODE_X86){
        Elf32_Ehdr *header_local = (Elf32_Ehdr *)header;
        return header_local->e_shentsize * header_local->e_shnum;
    }
    if (mode == ELF_MODE_X86_64){
        Elf64_Ehdr *header_local = (Elf64_Ehdr *)header;
        return header_local->e_shentsize * header_local->e_shnum;
    }
    return 0;
}

bool Elf::Setup(int input_mode){
    switch(input_mode){
        case ELF_MODE_X86:
            header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
            mode = ELF_MODE_X86;
            break;
        case ELF_MODE_X86_64:
            header = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
            mode = ELF_MODE_X86_64;
            break;
        default:
            fprintf(stderr, "[x] unsupported elf executable mode\n");
            mode = ELF_MODE_UNSET;
            return false;
    }
    return true;
}

bool Elf::ReadSectionHeaders(){
    if (mode == ELF_MODE_X86){
        Elf32_Ehdr *header_local = (Elf32_Ehdr *)header;
        Elf32_Shdr *sh_table_local = (Elf32_Shdr *)sh_table;
        fseek(fd, header_local->e_shoff, SEEK_SET);
        fread(sh_table_local, 1, GetSectionTableSize(), fd);
        sh_str = (char *)malloc(sh_table_local[header_local->e_shstrndx].sh_size);
        if (sh_str == NULL){
            return false;
        }
        fseek(fd, sh_table_local[header_local->e_shstrndx].sh_offset, SEEK_SET);
        fread(sh_str, 1, sh_table_local[header_local->e_shstrndx].sh_size, fd);
        return true;
    }
    if (mode == ELF_MODE_X86_64){
        Elf64_Ehdr *header_local = (Elf64_Ehdr *)header;
        Elf64_Shdr *sh_table_local = (Elf64_Shdr *)sh_table;
        fseek(fd, header_local->e_shoff, SEEK_SET);
        fread(sh_table_local, 1, GetSectionTableSize(), fd);
        sh_str = (char *)malloc(sh_table_local[header_local->e_shstrndx].sh_size);
        if (sh_str == NULL){
            return false;
        }
        fseek(fd, sh_table_local[header_local->e_shstrndx].sh_offset, SEEK_SET);
        fread(sh_str, 1, sh_table_local[header_local->e_shstrndx].sh_size, fd);
        return true;
    }
    return false;
}

bool Elf::ReadFile(char *file_path){
    fd = fopen(file_path, "rb");
    if (fd == NULL){
        fprintf(stderr, "[x] failed to open %s\n", file_path);
        return false;
    }
    fseek(fd, 0, SEEK_SET);
    if (mode == ELF_MODE_X86){
        Elf32_Ehdr *header_local = (Elf32_Ehdr *)header;
        fread(header_local, sizeof(Elf32_Ehdr), 1, fd);
        if (is_arch(EM_386) == false){
            fprintf(stderr, "[x] the file %s is not an x86 binary\n", file_path);
            return false;
        }
        sh_table = (Elf32_Shdr *)malloc(GetSectionTableSize());
    }
    if (mode == ELF_MODE_X86_64){
        Elf64_Ehdr *header_local = (Elf64_Ehdr *)header;
        fread(header_local, sizeof(Elf64_Ehdr), 1, fd);
        if (is_arch(EM_X86_64) == false){
            fprintf(stderr, "[x] the file %s is not an x86_64 binary\n", file_path);
            return false;
        }
        sh_table = (Elf64_Shdr *)malloc(GetSectionTableSize());
    }
    if (is_elf()  == false){
        fprintf(stderr, "[x] the file %s is not a valid ELF executable\n", file_path);
        return false;
    }
    ReadSectionHeaders();
    GetExecutableData();
    return true;
}

bool Elf::GetExecutableData(){
    if (mode == ELF_MODE_X86){
        int section_index = 0;
        Elf32_Ehdr *header_local = (Elf32_Ehdr *)header;
        Elf32_Shdr *sh_table_local = (Elf32_Shdr *)sh_table;
        for(int i = 0; i < header_local->e_shnum; i++){
            if (sh_table_local[i].sh_flags & SHF_EXECINSTR){
                sections[section_index].offset = sh_table_local[i].sh_offset;
                sections[section_index].size = sh_table_local[i].sh_size;
                sections[section_index].data = malloc(sh_table_local[i].sh_size);
                if (sections[section_index].data == NULL){
                    return false;
                }
                fseek(fd, sections[section_index].offset, SEEK_SET);
                fread(sections[section_index].data, sh_table_local[i].sh_size, 1, fd);
                section_index++;
            }
        }
        return true;
    }
    if (mode == ELF_MODE_X86_64){
        Elf64_Ehdr *header_local = (Elf64_Ehdr *)header;
        Elf64_Shdr *sh_table_local = (Elf64_Shdr *)sh_table;
        int section_index = 0;
        for(int i = 0; i < header_local->e_shnum; i++){
            if (sh_table_local[i].sh_flags & SHF_EXECINSTR){
                sections[section_index].offset = sh_table_local[i].sh_offset;
                sections[section_index].size = sh_table_local[i].sh_size;
                sections[section_index].data = malloc(sh_table_local[i].sh_size);
                if (sections[section_index].data == NULL){
                    return false;
                }
                fseek(fd, sections[section_index].offset, SEEK_SET);
                fread(sections[section_index].data, sh_table_local[i].sh_size, 1, fd);
                section_index++;
            }
        }
        return true;
    }
    return false;
}

Elf::~Elf(){
    if (header != NULL){
        free(header);
        header = NULL;
    }
    if (sh_table != NULL){
        free(sh_table);
        sh_table = NULL;
    }
    if (sh_str != NULL){
        free(sh_str);
        sh_str = NULL;
    }
    if (fd != NULL){
        fclose(fd);
        fd = NULL;
    }
    for (int i = 0; i < ELF_MAX_SECTIONS; i++){
        if (sections[i].data != NULL){
            free(sections[i].data);
        }
    }
    SetSectionsDefault();
}
