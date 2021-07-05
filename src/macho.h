#include <stdio.h>
#include <stdlib.h>

#ifndef MACHO_H
#define MACHO_H

#define MACHO_MAX_SECTIONS 32

#define MACHO_MODE_UNSET  0
#define MACHO_MODE_X86    1
#define MACHO_MODE_X86_64 2

class Macho {
    private:
        struct section {
            int   offset;
            int   size;
            void *data;
        };
        struct header {
            uint32_t      magic;
            cpu_type_t    cputype;
            cpu_subtype_t cpusubtype;
            uint32_t      filetype;
            uint32_t      ncmds;
            uint32_t      sizeofcmds;
            uint32_t      flags;
        };
        struct segment {
            uint32_t  cmd;
            uint32_t  cmdsize;
            char      segname[16];
            uint32_t  vmaddr;
            uint32_t  vmsize;
            uint32_t  fileoff;
            uint32_t  filesize;
            vm_prot_t maxprot;
            vm_prot_t initprot;
            uint32_t  nsects;
            uint32_t  flags;
        };
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
