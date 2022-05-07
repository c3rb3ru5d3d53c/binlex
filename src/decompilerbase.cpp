#include "decompilerbase.h"

using namespace binlex;

DecompilerBase::DecompilerBase(const binlex::File &firef) : file_reference(firef) {
}

void DecompilerBase::py_SetThreads(uint threads, uint thread_cycles, uint thread_sleep) {
    g_args.options.threads = threads;
}

void DecompilerBase::py_SetCorpus(const char *corpus) {
    g_args.options.corpus = corpus;
}

void DecompilerBase::py_SetTags(const vector<string> &tags){
    g_args.options.tags = set<string>(tags.begin(), tags.end());
}

void DecompilerBase::py_SetInstructions(bool instructions) {
    g_args.options.instructions = instructions;
}

void DecompilerBase::py_SetMode(string mode){
    g_args.options.mode = mode;
}

// TODO we know how many exec sections we have, we don't need to go through all slots
// CV to fix by end of GeekWeek 2022
void DecompilerBase::WriteTraits(){
    std::ofstream output_stream;
    if (g_args.options.output != NULL) {
        output_stream.open(g_args.options.output);
        if(!output_stream.is_open()) {
            PRINT_ERROR_AND_EXIT("Unable to open file %s for writing\n", g_args.options.output);
        }
    }
    auto traits(GetTraits());
    if(g_args.options.output != NULL) {
	for(auto trait : traits) {
	    trait["file_sha256"] = file_reference.sha256;
	    trait["file_tlsh"] = file_reference.tlsh;
	    output_stream << (g_args.options.pretty ? trait.dump(4) : trait.dump()) << endl;
	}
    } else {
	for(auto trait : traits) {
	    trait["file_sha256"] = file_reference.sha256;
	    trait["file_tlsh"] = file_reference.tlsh;
	    cout << (g_args.options.pretty ? trait.dump(4) : trait.dump()) << endl;
	}
    }
    if (g_args.options.output != NULL) {
	output_stream.close();
    }
}
