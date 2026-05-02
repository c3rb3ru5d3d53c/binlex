#pragma once

#include <cstddef>
#include <cstdint>

extern "C" bool binlex_llvm_assemble_to_object(const char *triple_cstr,
                                                const char *cpu_cstr,
                                                const char *assembly_cstr,
                                                std::uint8_t **bytes,
                                                std::size_t *length,
                                                char **error);

extern "C" void binlex_llvm_free_bytes(std::uint8_t *bytes);
extern "C" void binlex_llvm_free_error(char *error);
