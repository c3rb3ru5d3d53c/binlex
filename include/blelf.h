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
    private:
      bool ParseSections();
    public:
      ARCH mode = ARCH::EM_NONE;
      unique_ptr<LIEF::ELF::Binary> binary;
      struct Section sections[BINARY_MAX_SECTIONS];
      uint32_t total_exec_sections;
      BINLEX_EXPORT ELF();
      BINLEX_EXPORT bool Setup(ARCH input_mode);
      virtual bool ReadVector(const std::vector<uint8_t> &data);
      BINLEX_EXPORT ~ELF();
    };
};

#endif
