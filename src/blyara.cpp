#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
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
            char *name;
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
                "blyara %s - A Binlex Yara Generation Utility\n"
                "  -i  --input\t\tinput file\t\t(optional)\n"
                "  -m  --metadata\tset metadata\t\t(optional)\n"
                "  -n  --name\t\tsignature name\n"
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
                if (strcmp(argv[i], (char *)"-n") == 0 ||
                    strcmp(argv[i], (char *)"--name") == 0){
                    if (argc < i+2){
                        fprintf(stderr, "[x] name requires 1 parameter\n");
                        exit(1);
                    }
                    options.name = argv[i+1];
                }
                if (strcmp(argv[i], (char *)"-c") == 0 ||
                    strcmp(argv[i], (char *)"--count") == 0){
                    if (argc < i+2){
                        fprintf(stderr, "[x] count requires 1 parameter\n");
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
            if (options.name == NULL){
                fprintf(stderr, "[x] name parameter is required\n");
                exit(1);
            }
            if (options.input == NULL){
                CollectStdinTraits();
            } else {
                CollectInputTraits();
            }
        }
        void CollectStdinTraits(){
            int count = 0;
            for (string line; getline(cin, line);) {
                options.traits["trait_" + to_string(count)] = "{" + line + "}";
                count++;
            }
        }
        void CollectInputTraits(){
            fstream input_file;
            input_file.open(options.input, ios::in);
            if (input_file.is_open()) {
                string line;
                int  count = 0;
                while (getline(input_file, line)) {
                    options.traits["trait_" + to_string(count)] = "{" + line + "}";
                    count++;
                }
                input_file.close();
            }
        }
        void SetDefault(){
            options.count = 1;
            options.name = NULL;
            options.input = NULL;
            options.output = NULL;
            options.help = false;
        }
        ~Args(){
            SetDefault();
        }
};

int main(int argc, char **argv){
    Args args;
    args.Parse(argc, argv);
    if (args.options.traits.is_null() == false){
        stringstream signature;
        signature << "rule " << args.options.name << " {" << endl;
        if (args.options.metadata.is_null() == false){
            signature << "    " << "meta:" << endl;
            for (json::iterator it = args.options.metadata.begin(); it != args.options.metadata.end(); ++it){
                signature << "        " << it.key() << " = " << it.value() << endl;
            }
        }
        signature << "    " << "strings:" << endl;
        for (json::iterator it = args.options.traits.begin(); it != args.options.traits.end(); ++it){
            signature << "        $" << it.key() << " = " << it.value().get<string>() << endl;
        }
        signature << "    " << "condition:" << endl;
        signature << "        " << to_string(args.options.count) << " of them" << endl;
        signature << "}" << endl;
        if (args.options.output == NULL){
            cout << signature.str();
        } else {
            FILE *fd = fopen(args.options.output, "w");
            fwrite(signature.str().c_str(), sizeof(char), signature.str().length(), fd);
            fclose(fd);
        }
    }
    return 0;
}
