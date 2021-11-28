#include <stdio.h>
#include <stdlib.h>

#ifndef ELF_H
#define ELF_H

#define ELF_MAX_SECTIONS 32

#define ELF_MODE_UNSET  0
#define ELF_MODE_X86    1
#define ELF_MODE_X86_64 2

class Elf{
    private:
        struct Section {
            uint offset;
            int size;
            void *data;
        };
        bool is_arch(int arch);
        bool is_elf();
        void SetSectionsDefault();
        unsigned int GetSectionTableSize();
        bool ReadSectionHeaders();
        bool GetExecutableData();
    public:
        char magic[4]  = {0x7F, 0x45, 0x4C, 0x46};
        FILE *fd       = NULL;
        void *header   = NULL;
        void *sh_table = NULL;
        char *sh_str   = NULL;
        int mode       = ELF_MODE_UNSET;
        struct Section sections[ELF_MAX_SECTIONS];
        Elf();
        bool Setup(int input_mode);
        bool ReadFile(char *file_path);
        ~Elf();
};

#endif
