#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <sys/poll.h>
#include "json.h"

using namespace std;
using json = nlohmann::json;

class Args{
    public:
        char version[7] = "v1.1.0";
        struct {
            json metadata;
            json traits;
            char *input;
            char *output;
            bool version;
            bool help;
            int count;
        } options;
        Args(){
            SetDefault();
        }
        void PrintHelp(){
            printf(
                "blyara %s - Binlex Yara Generator Utility\n"
                "  -i  --input\t\tinput file\t\t(optional)\n"
                "  -m  --metadata\tset metadata\t\t(required)\n"
                "  -c  --count\t\tcount\t\t\t(optional)\n"
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
                if (strcmp(argv[i], (char *)"-c") == 0 ||
                    strcmp(argv[i], (char *)"--count") == 0){
                    if (argc < i+2){
                        fprintf(stderr, "[x] count requires 1 parameters\n");
                        exit(1);
                    }
                    options.count = atoi(argv[i+1]);
                    if (options.count < 1){
                        fprintf(stderr, "[x] count must be greater or equal to 1\n");
                        exit(1);
                    }
                }
                if (strcmp(argv[i], (char *)"-m") == 0 ||
                    strcmp(argv[i], (char *)"--metadata") == 0){
                    if (argc < i+3){
                        fprintf(stderr, "[x] metadata requires 2 parameters\n");
                        exit(1);
                    }
                    options.metadata[argv[i+1]] = argv[i+2];
                    i = i + 2;
                }
            }
        }
        void SetDefault(){
            options.input = NULL;
            options.output = NULL;
            options.help = false;
        }
        ~Args(){
            SetDefault();
        }
};

bool is_stdin(){
    struct pollfd fds;
    fds.fd = 0;
    fds.events = POLLIN;
    if (poll(&fds, 1, 0) == 1){
        return true;
    }
    return false;
}

int main(int argc, char **argv){
    Args args;
    args.Parse(argc, argv);
    if (is_stdin() == true){
        int count = 0;
        for (string line; getline(cin, line);) {
            args.options.traits["trait_" + to_string(count)] = "{" + line + "}";
            count++;
        }
    }
    if (args.options.traits.is_null() == false){
        cout << args.options.traits.dump(4) << endl;
    }
    return 0;
}
