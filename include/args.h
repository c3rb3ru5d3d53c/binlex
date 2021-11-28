#ifndef ARGS_H
#define ARGS_H

#define ARGS_MODE_COUNT 7

#define ARGS_IO_TYPE_UNKNOWN 0
#define ARGS_IO_TYPE_FILE    1
#define ARGS_IO_TYPE_DIR     2

class Args {
    public:
        char version[7] = "v1.1.0";
        const char *modes[ARGS_MODE_COUNT] = {"elf:x86", "elf:x86_64", "pe:x86", "pe:x86_64", "raw:x86", "raw:x86_64", "raw:cil"};
        struct{
            char *input;
            int io_type;
            char *output;
            unsigned int threads;
            bool help;
            bool list_modes;
            char *mode;
            bool pretty;
        } options;
        Args();
        void SetDefault();
        bool check_mode(char *mode);
        int is_file(const char *path);
        int is_dir(const char *path);
        void set_io_type(char *input);
        void print_help();
        void parse(int argc, char **argv);
        ~Args();
};
#endif
