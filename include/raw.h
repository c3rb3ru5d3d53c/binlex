#include <stdio.h>
#include <stdlib.h>

#ifndef RAW_H
#define RAW_H

#define RAW_MAX_SECTIONS 128

class Raw{
    private:
        struct Section {
            void *data;
            int size;
            uint offset;
        };
        int GetFileSize(FILE *fd);
    public:
        struct Section sections[RAW_MAX_SECTIONS];
        Raw();
        bool ReadFile(char *file_path, int section_index);
        ~Raw();
};

#endif
