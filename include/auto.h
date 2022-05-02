#ifndef AUTO_H
#define AUTO_H

#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/LIEF.hpp>
#include "common.h"
#include "decompiler.h"

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif

using namespace std;

namespace binlex{
    class AutoLex{
    private:
        struct {
            LIEF::EXE_FORMATS format;
            cs_mode mode;
            cs_arch arch;
            int machineType;
        } characteristics;
        bool GetFileCharacteristics(char *file_path);
    public:
        BINLEX_EXPORT AutoLex();
        BINLEX_EXPORT bool HasLimitations(char *file_path);
        BINLEX_EXPORT bool IsDotNet(char *file_path);
        BINLEX_EXPORT Decompiler ProcessFile(char *file_path, uint threads, uint timeout, uint thread_cycles, useconds_t thread_sleep, bool instructions, char *corpus);
    };
};

#endif
