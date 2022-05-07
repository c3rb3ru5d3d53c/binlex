#ifndef ELF_H
#define ELF_H

#ifdef _WIN32
#include <Windows.h>
#endif

#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/ELF.hpp>
#include <exception>
#include <stdexcept>
#include <cassert>
#include "file.h"

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif

using namespace std;
using namespace LIEF::ELF;

namespace binlex{
  class ELF : public File{
    /**
    This class is used to read ELF files.
    */
    private:
      /**
	    This method parses the ELF file sections.
	    @return bool
	    */
      bool ParseSections();
    public:
      ARCH mode = ARCH::EM_NONE;
      unique_ptr<LIEF::ELF::Binary> binary;
      struct Section sections[BINARY_MAX_SECTIONS];
      uint32_t total_exec_sections;
      BINLEX_EXPORT ELF();
      /**
	    This method sets the architecture of the ELF file you wish to read.
	    @param input_mode architecure of the file
	    @return bool
	    */
      BINLEX_EXPORT bool Setup(ARCH input_mode);
      /**
	    This method reads an ELF file from a buffer.
	    @param data vector
	    @return bool
	    */
      virtual bool ReadVector(const std::vector<uint8_t> &data);
      BINLEX_EXPORT ~ELF();
    };
};

#endif
