#ifndef DECOMPILERBASE_H
#define DECOMPILERBASE_H

#include <stdint.h>
#include <capstone/capstone.h>
#include "json.h"
#include "file.h"

using json = nlohmann::json;

namespace binlex {
    class DecompilerBase : public Common {
        protected:
            const binlex::File &file_reference;
        public:
            DecompilerBase(const binlex::File &firef);

            /**
             * Get Traits as JSON
             * @return list of traits json objects
             */
            virtual vector<json> GetTraits() = 0;

            /**
            Write Traits to output or file
            This function usees GetTraits() to get the traits data as a json.
            */
            BINLEX_EXPORT void WriteTraits();

            /*
            * The following functions are for pybind-only use. They offer a way to pass arguments to
            * the CPP code, which otherwise if obtained via command-line arguments.
            */
            /**
            Set Threads and Thread Cycles, via pybind11
            @param threads number of threads
            @param thread_cycles thread cycles
            @param index the section index
            */
            BINLEX_EXPORT void py_SetThreads(uint threads, uint thread_cycles, uint thread_sleep);

            /**
            Sets The Corpus Name, via pybind11
            @param corpus pointer to corpus name
            @param index the section index
            */
            BINLEX_EXPORT void py_SetCorpus(const char *corpus);

            /**
            Specify if instruction traits are collected, via pybind11
            @param instructions bool to collect instructions traits or not
            @param index the section index
            */
            BINLEX_EXPORT void py_SetInstructions(bool instructions);

            /**
             Sets the tags, via pybind11
            @param tags set of tags
            */
            BINLEX_EXPORT void py_SetTags(const vector<string> &tags);
            BINLEX_EXPORT void py_SetMode(string mode);
    };
}
#endif
