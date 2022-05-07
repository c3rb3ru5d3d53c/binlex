#ifndef AUTO_H
#define AUTO_H

#ifdef _WIN32
#include <Windows.h>
#endif

#include "pe.h"
#include "pe-dotnet.h"
#include "blelf.h"
#include "decompiler.h"
#include "cil.h"
#include "common.h"
#include <LIEF/LIEF.hpp>
#include <LIEF/PE.hpp>

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif

using namespace std;

namespace binlex{
    class AutoLex{
        /**
        This class is used to process files with auto mode.
        */
        private:
            struct {
                LIEF::EXE_FORMATS format;
                cs_mode mode;
                cs_arch arch;
                int machineType;
            } characteristics;
            /**
            Get initial characteristics of a file.
            @param file_path path to the file to read
            @return bool
            */
            bool GetFileCharacteristics(char *file_path);
        public:
            BINLEX_EXPORT AutoLex();
            /**
            This method processes a files for auto mode.
            @param file_path path to the file to read
            @return int result
            */
            BINLEX_EXPORT int ProcessFile(char *file_path);
    };
};

#endif
