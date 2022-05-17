#ifndef ARGS_H
#define ARGS_H

#include <set>
#include <string>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif

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
                bool help;
                bool list_modes;
                std::string mode;
                std::string corpus;
                bool pretty;
                bool debug;
                std::set<std::string> tags; //!< Set for storing the tags.
            } options;
            BINLEX_EXPORT Args();
            /**
             * Set the default CLI parameters.
             * @return void
             */
            BINLEX_EXPORT void SetDefault();
            /**
             * Check the CLI mode provided by the user.
             * @param mode the mode provided
             * @return bool
             */
            BINLEX_EXPORT bool check_mode(const char *mode);
            /**
             * Check if path to file is valid.
             * @param path file path
             * @return int result
             */
            BINLEX_EXPORT int is_file(const char *path);
            /**
             * Check if path is a directory.
             * @param path path to a directory
             * @return int result
             */
            BINLEX_EXPORT int is_dir(const char *path);
            /**
             * Set input type.
             * @param input file path or directory
             * @return void
             */
            BINLEX_EXPORT void set_io_type(char *input);
            /**
             * Print CLI help menu.
             * @return void
             */
            BINLEX_EXPORT void print_help();
            /**
             * Parse CLI arguments.
             * @return void
             */
            BINLEX_EXPORT void parse(int argc, char **argv);
            /**
             * Get tags from CLI as string.
             * @return std::string
             */
	        BINLEX_EXPORT std::string get_tags_as_str();
            BINLEX_EXPORT ~Args();
    };
}

#endif
