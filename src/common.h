#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifndef COMMON_H
#define COMMON_H

void common_hex_dump(const char * desc, const void * addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL)
        printf ("%s:\n", desc);

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    else if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.

            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
}

char * common_hexdump_mem_disp(long int disp){
    int size = sizeof(disp) * 2 + sizeof(disp);
    char *buffer0 = (char *)malloc(size);
    memset((void *)buffer0, 0, size);
    const unsigned char * pc = (const unsigned char *)&disp;
    int count = 0;
    for (int i = 0; i < sizeof(disp) -1 ; i++){
        if (pc[i] != 0 && pc[i] != 255){
            if (count == 0){
                sprintf(buffer0, "%s%02x", buffer0, pc[i]);
            } else {
                sprintf(buffer0, "%s %02x", buffer0, pc[i]);
            }
            count++;
        }
    }
    return buffer0;
}

char * common_hexdump_le(const void *data, int size){
    int buffer_size = size * 2 + size;
    char *buffer0 = (char *)malloc(buffer_size);
    memset((void *)buffer0, 0, buffer_size);
    const unsigned char * pc = (const unsigned char *)data;
    int count = 0;
    for (int i = size - 1; i >= 0; i--){
        if (count == 0){
            sprintf(buffer0, "%s%02x", buffer0, pc[i]);
        } else {
            sprintf(buffer0, "%s %02x", buffer0, pc[i]);
        }
        count++;
    }
    return buffer0;
}

char * common_hexdump_be(const void *data, int size){
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

char * common_wildcard_bytes(char *str, char *wild){
    char wildcard[] = "??";
    char *offset = strstr(str, wild);
    if (offset != 0){
        for (int i = 0; i < strlen(wild);){
            memcpy(offset + i, &wildcard, 2);
            i = i + 3;
        }
    }
    return offset;
}

void common_wildcard_null(char *bytes){
    char wildcard[] = "??";
    char *buffer0 = (char *)malloc(3);
    memset(buffer0, 0, 3);
    for (int i = strlen(bytes) + 1; i >= 0;){
        i = i - 3;
        if (i < 0){
            break;
        }
        memcpy(buffer0, bytes + i, 2);
        if (strcmp(buffer0, (char *)"00") == 0){
            memcpy(bytes + i, &wildcard, 2);
        } else {
            break;
        }
    }
    free(buffer0);
}

#endif
