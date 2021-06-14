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

#define DECOMPILE_MODE_FUNCS 0
#define DECOMPILE_MODE_BLOKS 1

extern int errno;

// class Elf32 {
//     public:
//         char magic[4] = {0x7F, 0x45, 0x4C, 0x46};
//         Elf32_Ehdr *header;
//         Elf32() {
//             header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
//         };
//         int ReadFileHeader(const char * file_path){
//             FILE *file = fopen(file_path, "rb");
//             if (file != NULL){
//                 fread(header, sizeof(header), 1, file);
//                 fclose(file);
//             } else {
//                 return errno;
//             }
//             return 0;
//         }
//         bool CheckFileType(){
//             int result = memcmp(header->e_ident, magic, sizeof(magic));
//             if (result == 0){
//                 return true;
//             }
//             return false;
//         }
//         unsigned int GetArchitecture(){
//             return header->e_machine;
//         }
//         int GetType(){
//             return header->e_type;
//         }
//         ~Elf32() {
//             free(header);
//         }
// };

class Elf32{
    private:
        bool ReadElfHeader(){
            fseek(file, 0, SEEK_SET);
            fread(header, sizeof(Elf32_Ehdr), 1, file);
            if (ferror(file)){
                return false;
            }
            return true;
        }
        bool ReadElfSectionHeaders(){
            sh_table = (Elf32_Shdr *)malloc(GetSectionHeaderTableSize());
            fseek(file, header->e_shoff, SEEK_SET);
            fread(sh_table, 1, GetSectionHeaderTableSize(), file);
            sh_str = (char *)malloc(sh_table[header->e_shstrndx].sh_size);
            if (sh_str != NULL){
                fseek(file, sh_table[header->e_shstrndx].sh_offset, SEEK_SET);
                fread(sh_str, 1, sh_table[header->e_shstrndx].sh_size, file);
            } else {
                return false;
            }
            if (ferror(file)){
                return false;
            }
            return true;
        }
    public:
        char magic[4] = {0x7F, 0x45, 0x4C, 0x46};
        FILE *file = NULL;
        Elf32_Ehdr *header = NULL;
        Elf32_Shdr *sh_table = NULL;
        char *sh_str = NULL;
        int s_size = 0;
        int s_offset = 0;
        void *s_data = NULL;
        Elf32() {
            header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
        };
        int ReadFile(char * file_path){
            file = fopen(file_path, "rb");
            if (file != NULL){
                if (ReadElfHeader() == false){
                    return errno;
                }
                if (ReadElfSectionHeaders() == false){
                    return errno;
                }
            } else {
                return errno;
            }
            return 0;
        }
        bool CheckFileType(){
            int result = memcmp(header->e_ident, magic, sizeof(magic));
            if (result == 0){
                return true;
            }
            return false;
        }
        unsigned int GetArchitecture(){
            return header->e_machine;
        }
        int GetType(){
            return header->e_type;
        }
        unsigned int GetNumberOfSections(){
            return header->e_shnum;
        }
        unsigned int GetSectionHeaderTableSize(){
            return header->e_shentsize * header->e_shnum;
        }
        bool GetSection(char *section_name){
            for(int i = 0; i < header->e_shnum; i++){
                if(!strcmp(section_name, (sh_str + sh_table[i].sh_name))){
                    s_offset = sh_table[i].sh_offset;
                    s_size = sh_table[i].sh_size;
                    s_data = malloc(s_size);
                    if (s_data == NULL){
                        return false;
                    }
                    fseek(file, s_offset, SEEK_SET);
                    fread(s_data, s_size, 1, file);
                    return true;
                }
            }
            return false;
        }
        void FreeSection(){
            s_size = 0;
            s_offset = 0;
            if (s_data != NULL){
                free(s_data);
            }
        }
        ~Elf32() {
            if (header != NULL){
                free(header);
            }
            if (sh_table != NULL){
                free(sh_table);
            }
            if (sh_str != NULL){
                free(sh_str);
            }
            if (file != NULL){
                fclose(file);
            }
            FreeSection();
        }
};

class Elf64{
    private:
        bool ReadElfHeader(){
            fseek(file, 0, SEEK_SET);
            fread(header, sizeof(Elf64_Ehdr), 1, file);
            if (ferror(file)){
                return false;
            }
            return true;
        }
        bool ReadElfSectionHeaders(){
            sh_table = (Elf64_Shdr *)malloc(GetSectionHeaderTableSize());
            fseek(file, header->e_shoff, SEEK_SET);
            fread(sh_table, 1, GetSectionHeaderTableSize(), file);
            sh_str = (char *)malloc(sh_table[header->e_shstrndx].sh_size);
            if (sh_str != NULL){
                fseek(file, sh_table[header->e_shstrndx].sh_offset, SEEK_SET);
                fread(sh_str, 1, sh_table[header->e_shstrndx].sh_size, file);
            } else {
                return false;
            }
            if (ferror(file)){
                return false;
            }
            return true;
        }
    public:
        char magic[4] = {0x7F, 0x45, 0x4C, 0x46};
        FILE *file = NULL;
        Elf64_Ehdr *header = NULL;
        Elf64_Shdr *sh_table = NULL;
        char *sh_str = NULL;
        int s_size = 0;
        int s_offset = 0;
        void *s_data = NULL;
        Elf64() {
            header = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
        };
        int ReadFile(char * file_path){
            file = fopen(file_path, "rb");
            if (file != NULL){
                if (ReadElfHeader() == false){
                    return errno;
                }
                if (ReadElfSectionHeaders() == false){
                    return errno;
                }
            } else {
                return errno;
            }
            return 0;
        }
        bool CheckFileType(){
            int result = memcmp(header->e_ident, magic, sizeof(magic));
            if (result == 0){
                return true;
            }
            return false;
        }
        unsigned int GetArchitecture(){
            return header->e_machine;
        }
        int GetType(){
            return header->e_type;
        }
        unsigned int GetNumberOfSections(){
            return header->e_shnum;
        }
        unsigned int GetSectionHeaderTableSize(){
            return header->e_shentsize * header->e_shnum;
        }
        bool GetSection(char *section_name){
            for(int i = 0; i < header->e_shnum; i++){
                if(!strcmp(section_name, (sh_str + sh_table[i].sh_name))){
                    s_offset = sh_table[i].sh_offset;
                    s_size = sh_table[i].sh_size;
                    s_data = malloc(s_size);
                    if (s_data == NULL){
                        return false;
                    }
                    fseek(file, s_offset, SEEK_SET);
                    fread(s_data, s_size, 1, file);
                    return true;
                }
            }
            return false;
        }
        void FreeSection(){
            s_size = 0;
            s_offset = 0;
            if (s_data != NULL){
                free(s_data);
            }
        }
        ~Elf64() {
            if (header != NULL){
                free(header);
            }
            if (sh_table != NULL){
                free(sh_table);
            }
            if (sh_str != NULL){
                free(sh_str);
            }
            if (file != NULL){
                fclose(file);
            }
            FreeSection();
        }
};

#endif
