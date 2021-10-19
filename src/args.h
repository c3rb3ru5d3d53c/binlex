#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef ARGS_H
#define ARGS_H

#define ARGS_MODE_COUNT 7

#define ARGS_IO_TYPE_UNKNOWN 0
#define ARGS_IO_TYPE_FILE    1
#define ARGS_IO_TYPE_DIR     2

class Args{
    private:
        void SetDefault(){
            options.input = NULL;
            options.threads = 1;
            options.help = false;
            options.output = NULL;
            options.list_modes = false;
            options.mode = NULL;
            options.io_type = ARGS_IO_TYPE_UNKNOWN;
        }
        bool check_mode(char *mode){
            for (int i = 0; i < ARGS_MODE_COUNT; i++){
                if (strcmp(modes[i], mode) == 0){
                    return true;
                }
            }
            return false;
        }
        int is_file(const char *path){
            struct stat path_stat;
            if (stat(path, &path_stat) != 0){
                return 0;
            }
            return S_ISREG(path_stat.st_mode);
        }
        int is_dir(const char *path) {
            struct stat statbuf;
            if (stat(path, &statbuf) != 0){
                return 0;
            }
            return S_ISDIR(statbuf.st_mode);
        }
        void set_io_type(char *input){
            if (is_file(input) != 0){
                options.io_type = ARGS_IO_TYPE_FILE;
            } else if (is_dir(input) != 0){
                options.io_type = ARGS_IO_TYPE_DIR;
            } else{
                options.io_type = ARGS_IO_TYPE_UNKNOWN;
                fprintf(stderr, "unknown input type\n");
                exit(1);
            }
        }
    public:
        char version[7]      = "v1.0.0";
        const char *modes[ARGS_MODE_COUNT] = {"elf:x86", "elf:x86_64", "pe:x86", "pe:x86_64", "raw:x86", "raw:x86_64", "macho:x86_64"};
        struct{
            char *input;
            int io_type;
            char *output;
            unsigned int threads;
            bool help;
            bool list_modes;
            char *mode;
        } options;
        Args(){
           SetDefault();
        }
        void print_help(){
            printf(
                "binlex %s - A Binary Genetic Traits Lexer\n"
                "  -i  --input\t\tinput file or directory\t\t(required)\n"
                "  -m  --mode\t\tset mode\t\t\t(required)\n"
                "  -lm --list-modes\tlist modes\n"
                "  -h  --help\t\tdisplay help\n"
                "  -t  --threads\t\tthreads\n"
                "  -o  --output\t\toutput file or directory\t(optional)\n"
                "  -v  --version\t\tdisplay version\n"
                "Author: @c3rb3ru5d3d53c\n",
                version
            );
        }

        void parse(int argc, char **argv){
            if (argc < 2){
                print_help();
                exit(0);
            }
            for (int i = 0; i < argc; i++){
                if (strcmp(argv[i], (char *)"-h") == 0 ||
                    strcmp(argv[i], (char *)"--help") == 0){
                    options.help = true;
                    print_help();
                    exit(0);
                }
                if (strcmp(argv[i], (char *)"-v") == 0 ||
                    strcmp(argv[i], (char *)"--version") == 0){
                    options.help = true;
                    printf("%s\n", version);
                    exit(0);
                }
                if (strcmp(argv[i], (char *)"-lm") == 0 ||
                    strcmp(argv[i], (char *)"--list-modes") == 0){
                    options.list_modes = true;
                    for (int j = 0; j < ARGS_MODE_COUNT; j++){
                        printf("%s\n", modes[j]);
                    }
                    exit(0);
                }
                if (strcmp(argv[i], (char *)"-i") == 0 ||
                    strcmp(argv[i], (char *)"--input") == 0){
                    options.input = argv[i+1];
                    set_io_type(options.input);
                }
                if (strcmp(argv[i], (char *)"-t") == 0 ||
                    strcmp(argv[i], (char *)"--threads") == 0){
                    options.threads = atoi(argv[i+1]);
                }
                if (strcmp(argv[i], (char *)"-o") == 0 ||
                    strcmp(argv[i], (char *)"--output") == 0){
                    options.output = argv[i+1];
                }
                if (strcmp(argv[i], (char *)"-m") == 0 ||
                    strcmp(argv[i], (char *)"--mode") == 0){
                    options.mode = argv[i+1];
                    if (check_mode(options.mode) == false){
                        fprintf(stderr, "%s is an invalid mode\n", options.mode);
                        exit(1);
                    }
                }
            }
        }
        ~Args(){
            SetDefault();
        }
};

#endif
