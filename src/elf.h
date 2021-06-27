#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <assert.h>
#include <capstone/capstone.h>
#include "common.h"

#ifndef ELF_H
#define ELF_H

#define ELF_MAX_SECTIONS 32

#define ELF_MODE_UNSET  0
#define ELF_MODE_X86    1
#define ELF_MODE_X86_64 2

extern int errno;

class Elf {
    private:
        struct Section {
            int offset;
            int size;
            void *data;
        };
        char * hexdump_be(const void *data, int size){
            int buffer_size = size * 2 + size;
            char *buffer0 = (char *)malloc(buffer_size);
            memset((void *)buffer0, 0, buffer_size);
            const unsigned char * pc = (const unsigned char *)data;
            int count = 0;
            for (int i = 0; i < size; i++){
                if (count == 0){
                    sprintf(buffer0, "%s%02x", buffer0, pc[i]);
                } else {
                    sprintf(buffer0, "%s %02x", buffer0, pc[i]);
                }
                count++;
            }
            return buffer0;
        }
        bool is_arch(int arch){
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
        bool is_elf(){
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
        unsigned int GetSectionTableSize(){
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
        void SetSectionsDefault(){
            for (int i = 0; i < ELF_MAX_SECTIONS; i++){
                sections[i].data = NULL;
                sections[i].offset = 0;
                sections[i].size = 0;
            }
        }
    public:
        char magic[4]  = {0x7F, 0x45, 0x4C, 0x46};
        FILE *fd       = NULL;
        void *header   = NULL;
        void *sh_table = NULL;
        char *sh_str   = NULL;
        int mode       = ELF_MODE_UNSET;
        struct Section sections[ELF_MAX_SECTIONS];
        Elf(){
            SetSectionsDefault();
        }
        bool Setup(int input_mode){
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
        bool ReadSectionHeaders(){
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
        bool ReadFile(char *file_path){
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
            return true;
        }
        bool GetExecutableData(){
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
                        //printf("%s\n", (sh_str + sh_table_local[i].sh_name));
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
                        //printf("%s\n", (sh_str + sh_table_local[i].sh_name));
                        section_index++;
                    }
                }
                return true;
            }
            return false;
        }
        ~Elf(){
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
};

#endif
