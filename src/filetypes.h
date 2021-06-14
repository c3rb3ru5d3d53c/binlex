#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifndef FILE_TYPES_H
#define FILE_TYPES_H

#define FILE_TYPE_UNSUPPORTED 0
#define FILE_TYPE_ELF_32      1
#define FILE_TYPE_ELF_64      2

extern int errno;

class FileTypes {
    private:
        bool ReadHeader(void *header, size_t size){
            fseek(file, 0, SEEK_SET);
            fread(header, size, 1, file);
            if (ferror(file)){
                return false;
            }
            return true;
        }
        int GetFileSize(){
            int cursor = ftell(file);
            fseek(file, 0, SEEK_END);
            int size = ftell(file);
            fseek(file, cursor, SEEK_SET);
            return size;
        }
    public:
        FILE *file;
        Elf32_Ehdr *elf_header;
        char elf_magic[4] = {0x7F, 0x45, 0x4C, 0x46};
        int file_type = FILE_TYPE_UNSUPPORTED;
        FileTypes(){
            elf_header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
        }
        int GetType(char *file_path){
            file = fopen(file_path, "rb");
            if (file == NULL){
                return -1;
            }
            if (GetFileSize() >= sizeof(Elf32_Ehdr)){
                ReadHeader(elf_header, sizeof(Elf32_Ehdr));
                if (memcmp(elf_header->e_ident, elf_magic, sizeof(elf_magic)) == 0){
                    switch(elf_header->e_machine){
                        case EM_386:
                            file_type = FILE_TYPE_ELF_32;
                            return file_type;
                        case EM_X86_64:
                            file_type = FILE_TYPE_ELF_64;
                            return file_type;
                        default:
                            break;
                    }
                }
            }
            return FILE_TYPE_UNSUPPORTED;
        }
        ~FileTypes(){
            free(elf_header);
        }
};

#endif