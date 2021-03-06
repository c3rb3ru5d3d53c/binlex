#ifndef PE_H
#define PE_H

#ifdef _WIN32
#include <Windows.h>
#include <stdexcept>
#endif

#include <iostream>
#include <memory>
#include <set>
#include <LIEF/PE.hpp>
#include "common.h"
#include "file.h"
#include <vector>
#include <cassert>

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif

using namespace std;
using namespace LIEF::PE;

namespace binlex {
  class PE : public File{
        /**
         * This class is for reading PE files or buffers.
         */
        private:
            bool ParseSections();
        public:
            #ifndef _WIN32
                MACHINE_TYPES mode = MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN;
            #else
                MACHINE_TYPES mode = MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN;
            #endif
            unique_ptr<LIEF::PE::Binary> binary;
            BINLEX_EXPORT PE();
            //struct Section sections[BINARY_MAX_SECTIONS];
            //uint32_t total_exec_sections;
            /**
             * Check if the PE file is a .NET file
             * @return bool
             */
            BINLEX_EXPORT bool IsDotNet();
            /**
             * Check if the file has limitations that may result in invalid traits.
             * @return bool
             */
            BINLEX_EXPORT bool HasLimitations();
            /**
             * Read data vector pointer.
             * @param data vector of uint8_t data.
             * @return bool
             */
	        virtual bool ReadVector(const std::vector<uint8_t> &data);
            BINLEX_EXPORT ~PE();
    };
};

#endif
