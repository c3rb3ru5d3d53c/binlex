#ifndef ARGS_H
#define ARGS_H

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT 
#endif

#define ARGS_MODE_COUNT 9

#define ARGS_IO_TYPE_UNKNOWN 0
#define ARGS_IO_TYPE_FILE    1
#define ARGS_IO_TYPE_DIR     2

#ifdef _WIN32
typedef unsigned int uint;
typedef uint useconds_t;
#endif

/**
* @namespace binlex
* @brief the binlex namespace
*/
namespace binlex{
    class Args {
        public:
            char version[7] = "v1.1.1";
            const char *modes[ARGS_MODE_COUNT] = {"elf:x86", "elf:x86_64", "pe:x86", "pe:x86_64", "raw:x86", "raw:x86_64", "raw:cil", "pe:cil", "auto"};
            struct{
                char *input;
                int io_type;
                char *output;
                uint timeout;
                uint threads;
                uint thread_cycles;
                useconds_t thread_sleep;
                bool help;
                bool list_modes;
                bool instructions;
                char *mode;
                char *corpus;
                bool pretty;
            } options;
            BINLEX_EXPORT Args();
            BINLEX_EXPORT void SetDefault();
            BINLEX_EXPORT bool check_mode(char *mode);
            BINLEX_EXPORT int is_file(const char *path);
            BINLEX_EXPORT int is_dir(const char *path);
            BINLEX_EXPORT void set_io_type(char *input);
            BINLEX_EXPORT void print_help();
            BINLEX_EXPORT void parse(int argc, char **argv);
            BINLEX_EXPORT ~Args();
    };
}
#endif
