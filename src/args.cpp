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
#include <sstream>
#include "args.h"

using namespace binlex;

Args::Args(){
    SetDefault();
}

void Args::SetDefault(){
    options.timeout = 0;
    options.instructions = false;
    options.input = NULL;
    options.threads = 1;
    options.help = false;
    options.output = NULL;
    options.corpus = "default";
    options.list_modes = false;
    options.mode = "auto";
    options.io_type = ARGS_IO_TYPE_UNKNOWN;
    options.pretty = false;
    options.debug = false;
    options.tags.clear(); // Clear if defaults are needed.
}

bool Args::check_mode(const char *mode){
    for (int i = 0; i < ARGS_MODE_COUNT; i++){
        if (strcmp(modes[i], mode) == 0){
            return true;
        }
    }
    return false;
}

int Args::is_file(const char* path) {
#ifndef _WIN32
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return 0;
    }
    return S_ISREG(path_stat.st_mode);
#else
    DWORD dwFileAttributes = GetFileAttributesA(path);
    return !(dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
#endif
}

int Args::is_dir(const char* path) {
#ifndef _WIN32
    struct stat statbuf;
    if (stat(path, &statbuf) != 0) {
        return 0;
    }
    return S_ISDIR(statbuf.st_mode);
#else
    DWORD dwFileAttributes = GetFileAttributesA(path);
    return dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
#endif
}

void Args::set_io_type(char *input){
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

std::string Args::get_tags_as_str(){
    std::ostringstream out;

    if(!options.tags.empty()) {
	auto tbegin = options.tags.begin();
	auto tend = options.tags.end();
	out << *tbegin;
	while((++tbegin) != tend){
	    out << ',' << *tbegin;
	}
    }
    return out.str();
}


void Args::print_help(){
    printf(
        "binlex %s - A Binary Genetic Traits Lexer\n"
        "  -i  --input\t\tinput file\t\t(required)\n"
        "  -m  --mode\t\tset mode\t\t(optional)\n"
        "  -lm --list-modes\tlist modes\t\t(optional)\n"
        "      --instructions\tinclude insn traits\t(optional)\n"
        "  -c  --corpus\t\tcorpus name\t\t(optional)\n"
        "  -g  --tag\t\tadd a tag\t\t(optional)\n"
        "           \t\t(can be specified multiple times)\n"
        "  -t  --threads\t\tnumber of threads\t(optional)\n"
        "  -to --timeout\t\texecution timeout in s\t(optional)\n"
        "  -h  --help\t\tdisplay help\t\t(optional)\n"
        "  -o  --output\t\toutput file\t\t(optional)\n"
        "  -p  --pretty\t\tpretty output\t\t(optional)\n"
        "  -d  --debug\t\tprint debug info\t(optional)\n"
        "  -v  --version\t\tdisplay version\t\t(optional)\n"
        "Author: @c3rb3ru5d3d53c\n",
        version
    );
}

void Args::parse(int argc, char **argv){
    if (argc < 1){
        print_help();
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < argc; i++){
        if (strcmp(argv[i], (char *)"-h") == 0 ||
            strcmp(argv[i], (char *)"--help") == 0){
            options.help = true;
            print_help();
            exit(EXIT_SUCCESS);
        }
        if (strcmp(argv[i], (char *)"-v") == 0 ||
            strcmp(argv[i], (char *)"--version") == 0){
            options.help = true;
            printf("%s\n", version);
            exit(EXIT_SUCCESS);
        }
        if (strcmp(argv[i], (char *)"-lm") == 0 ||
            strcmp(argv[i], (char *)"--list-modes") == 0){
            options.list_modes = true;
            for (int j = 0; j < ARGS_MODE_COUNT; j++){
                printf("%s\n", modes[j]);
            }
            exit(EXIT_SUCCESS);
        }
        if (strcmp(argv[i], (char *)"-i") == 0 ||
            strcmp(argv[i], (char *)"--input") == 0){
            options.input = argv[i+1];
            set_io_type(options.input);
        }
        if (strcmp(argv[i], (char *)"-p") == 0 ||
            strcmp(argv[i], (char *)"--pretty") == 0){
            options.pretty = true;
        }
        if (strcmp(argv[i], (char *)"--instructions") == 0){
            options.instructions = true;
        }
        if (strcmp(argv[i], (char *)"-t") == 0 ||
            strcmp(argv[i], (char *)"--threads") == 0){
            if (argc < i+2){
                fprintf(stderr, "[x] invalid thread count\n");
                exit(EXIT_FAILURE);
            }
            options.threads = atoi(argv[i+1]);
            if (options.threads <= 0){
                fprintf(stderr, "[x] invalid number of threads\n");
                exit(EXIT_FAILURE);
            }
        }
        if (strcmp(argv[i], (char *)"-to") == 0 ||
            strcmp(argv[i], (char *)"--timeout") == 0){
            if (argc < i+2){
                fprintf(stderr, "[x] timeout requires a parameter\n");
                exit(EXIT_FAILURE);
            }
            options.timeout = atoi(argv[i+1]);
            if (options.timeout <= 0){
                fprintf(stderr, "[x] invalid timeout value\n");
                exit(EXIT_FAILURE);
            }
        }
        if (strcmp(argv[i], (char *)"-c") == 0 ||
            strcmp(argv[i], (char *)"--corpus") == 0){
            if (argc < i+2){
                fprintf(stderr, "[x] corpus requres 1 parameter\n");
                exit(EXIT_FAILURE);
            }
            options.corpus = argv[i+1];
        }
        if (strcmp(argv[i], (char *)"-o") == 0 ||
            strcmp(argv[i], (char *)"--output") == 0){
            options.output = argv[i+1];
        }
        if (strcmp(argv[i], (char *)"-m") == 0 ||
            strcmp(argv[i], (char *)"--mode") == 0){
            options.mode = argv[i+1];

            if (check_mode(options.mode.c_str()) == false){
                fprintf(stderr, "%s is an invalid mode\n", options.mode.c_str());
                exit(EXIT_FAILURE);
            }
        }
        if (strcmp(argv[i], (char *)"-d") == 0 ||
            strcmp(argv[i], (char *)"--debug") == 0){
            options.debug = true;
            fprintf(stderr, "DEBUG ENABLED...\n");
	}
        if (strcmp(argv[i], (char *)"-g") == 0 ||
            strcmp(argv[i], (char *)"--tag") == 0){
            if (argc < i + 2){
                fprintf(stderr, "[x] tag requires a parameter\n");
                exit(EXIT_FAILURE);
            }
	    options.tags.insert(argv[i + 1]);
        }
    }
}

Args::~Args(){
    SetDefault();
}
