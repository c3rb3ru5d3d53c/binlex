#include <stdio.h>
#include <stdlib.h>
#include <string.h>

class Args{
    public:
        char version[7] = "v1.1.0";
        struct {
            char *input;
            char *output;
            bool version;
            bool help;
        } options;
        Args(){
            SetDefault();
        }
        void PrintHelp(){
            printf(
                "blyara %s - Binlex Yara Generator Utility\n"
                "  -i  --input\t\tinput file\t\t(optional)\n"
                "  -m  --metadata\tset metadata\t\t(required)\n"
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

int main(int argc, char **argv){
    Args args;
    args.Parse(argc, argv);
    return 0;
}
