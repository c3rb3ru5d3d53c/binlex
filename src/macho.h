#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifndef MACHO_H
#define MACHO_H

#define MACHO_MAX_SECTIONS 32

#define MACHO_MODE_UNSET  0
#define MACHO_MODE_X86    1
#define MACHO_MODE_X86_64 2

extern int errno;

class Macho {
    private:
        const char magic_0[4] = {'\xCE', '\xFA', '\xED', '\xFE'};
        const char magic_1[4] = {'\xFE', '\xED', '\xFA', '\xCE'};
        const char magic_2[4] = {'\xFE', '\xED', '\xFA', '\xCF'};
        struct section {
            int   offset;
            int   size;
            void  *data;
        };
        struct mach_header {
            uint32_t magic;
            int32_t	 cputype;
            int32_t  cpusubtype;
            uint32_t filetype;
            uint32_t ncmds;
            uint32_t sizeofcmds;
            uint32_t flags;
        };
        struct mach_header_64 {
            uint32_t magic;
            int32_t	 cputype;
            int32_t  cpusubtype;
            uint32_t filetype;
            uint32_t ncmds;
            uint32_t sizeofcmds;
            uint32_t flags;
            uint32_t reserved;
        };
        struct segment {
            uint32_t cmd;
            uint32_t cmdsize;
            char     segname[16];
            uint32_t vmaddr;
            uint32_t vmsize;
            uint32_t fileoff;
            uint32_t filesize;
            int32_t  maxprot;
            int32_t  initprot;
            uint32_t nsects;
            uint32_t flags;
        };
        bool is_macho(){
            uint32_t magic;
            int pos = ftell(fd);
            fseek(fd, 0, SEEK_SET);
            fread(&magic, sizeof(magic), 1, fd);
            fseek(fd, pos, SEEK_SET);
            if (memcmp(&magic_0, &magic, sizeof(magic)) == 1){
                return false;
            }
            return true;
        }
    public:
        FILE *fd;
        int mode = MACHO_MODE_UNSET;
        struct section sections[MACHO_MAX_SECTIONS];
        Macho(){
            for (int i = 0; i < MACHO_MAX_SECTIONS; i++){
                sections[i].offset = 0;
                sections[i].size = 0;
                sections[i].data = NULL;
            }
        }
        bool Setup(int input_mode){
            switch(input_mode){
                case MACHO_MODE_X86:
                    mode = MACHO_MODE_X86;
                    break;
                case MACHO_MODE_X86_64:
                    mode = MACHO_MODE_X86_64;
                    break;
                default:
                    fprintf(stderr, "[x] unsupported macho executable mode\n");
                    mode = MACHO_MODE_UNSET;
                    return false;
            }
            return true;
        }
        bool ReadFile(char *file_path, int index){
            fd = fopen(file_path, "rb");
            if (fd == NULL){
                 fprintf(stderr, "[x] %s", strerror(errno));
                 return false;
            }
            if (is_macho() == true){
                printf("is_macho: true\n");
            } else {
                printf("is_macho: false\n");
            }
            if (fclose(fd) != 0){
                fprintf(stderr, "[x] %s", strerror(errno));
                return false;
            }
            return true;
        }
        ~Macho(){
            for (int i = 0; i < MACHO_MAX_SECTIONS; i++){
                if (sections[i].data != NULL){
                    free(sections[i].data);
                    sections[i].size = 0;
                    sections[i].offset = 0;
                }
            }
        }
};

#endif
