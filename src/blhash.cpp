#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include "json.h"

using namespace std;
using json = nlohmann::json;

class Args{
    public:
        char version[7] = "v1.1.1";
        struct {
            json traits;
            char *input;
            char *name;
            char *output;
            char *mode;
            bool version;
            bool help;
        } options;
        Args(){
            SetDefault();
        }
        void PrintHelp(){
            printf(
                "blhash %s - Binlex Hash Utility\n"
                "  -i  --input\t\tinput file\t\t(optional)\n"
                "  -m  --mode\t\tset mode\t\t(optional)\n"
                "  -lm --list-modes\tlist modes(optional)\n"
                "  -h  --help\t\tdisplay help\n"
                "  -o  --output\t\toutput file\t\t(optional)\n"
                "  -v  --version\t\tdisplay version\n"
                "Author: @c3rb3ru5d3d53c\n",
                version
            );
        }
        void Parse(int argc, char **argv){
            for (int i = 0; i < argc; i++){
                if (strcmp(argv[i], (char *)"-h") == 0 ||
                    strcmp(argv[i], (char *)"--help") == 0){
                    options.help = true;
                    PrintHelp();
                    exit(0);
                }
                if (strcmp(argv[i], (char *)"-v") == 0 ||
                    strcmp(argv[i], (char *)"--version") == 0){
                    options.version = true;
                    printf("%s\n", version);
                    exit(0);
                }
                if (strcmp(argv[i], (char *)"-i") == 0 ||
                    strcmp(argv[i], (char *)"--input") == 0){
                    if (argc < i+2){
                        fprintf(stderr, "[x] input requires 1 parameter\n");
                        exit(1);
                    }
                    options.input = argv[i+1];
                }
                if (strcmp(argv[i], (char *)"-o") == 0 ||
                    strcmp(argv[i], (char *)"--output") == 0){
                    if (argc < i+2){
                        fprintf(stderr, "[x] input requires 1 parameter\n");
                        exit(1);
                    }
                    options.output = argv[i+1];
                }
                if (strcmp(argv[i], (char *)"-m") == 0 ||
                    strcmp(argv[i], (char *)"--mode") == 0){
                    if (argc < i+2){
                        fprintf(stderr, "[x] mode requires 1 parameters\n");
                        exit(1);
                    }
                    options.mode = argv[i+1];
                }
            }
        }
        void SetDefault(){
            options.mode = NULL;
            options.input = NULL;
            options.output = NULL;
            options.help = false;
            options.version = false;
        }
        ~Args(){
            SetDefault();
        }
};

int main(int argc, char **argv){
    Args args;
    args.Parse(argc, argv);
    return 0;
}
