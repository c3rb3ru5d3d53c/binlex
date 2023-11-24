cmake_minimum_required(VERSION 3.5)

project(deps)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(ExternalProject)

if(MSVC)
    add_definitions(-DNOMINMAX)
    # HACK: be compatible with the ExternalProject's that are built in Release mode
    string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
endif()

set(CAPSTONE_ROOT         "${CMAKE_BINARY_DIR}/capstone/")
set(CAPSTONE_INCLUDE_DIRS "${CAPSTONE_ROOT}/include/")
set(CAPSTONE_GIT_URL      "https://github.com/capstone-engine/capstone.git")
set(CAPSTONE_GIT_TAG      "4.0.2")

ExternalProject_Add(
    capstone
    PREFIX              "${CAPSTONE_ROOT}"
    INSTALL_DIR         "${CAPSTONE_ROOT}"
    GIT_REPOSITORY      "${CAPSTONE_GIT_URL}"
    GIT_TAG             "${CAPSTONE_GIT_TAG}"
    GIT_SHALLOW         ON
    CMAKE_ARGS          -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
                        -DCAPSTONE_BUILD_SHARED=OFF
                        -DCAPSTONE_BUILD_TESTS=OFF
                        -DCAPSTONE_MIPS_SUPPORT=OFF
                        -DCAPSTONE_ARM_SUPPORT=OFF
                        -DCAPSTONE_ARM64_SUPPORT=OFF
                        -DCAPSTONE_M68K_SUPPORT=OFF
                        -DCAPSTONE_TMS320C64X_SUPPORT=OFF
                        -DCAPSTONE_M680X_SUPPORT=OFF
                        -DCAPSTONE_EVM_SUPPORT=OFF
                        -DCAPSTONE_PPC_SUPPORT=OFF
                        -DCAPSTONE_SPARC_SUPPORT=OFF
                        -DCAPSTONE_SYSZ_SUPPORT=OFF
                        -DCAPSTONE_XCORE_SUPPORT=OFF
                        -DCAPSTONE_X86_SUPPORT=ON
                        -DCMAKE_OSX_SYSROOT=${CMAKE_OSX_SYSROOT}
                        -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
                        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
                        -DCMAKE_C_FLAGS_DEBUG=${CMAKE_C_FLAGS_DEBUG}
                        -DCMAKE_C_FLAGS_RELEASE=${CMAKE_C_FLAGS_RELEASE}
                        -DCMAKE_C_FLAGS_MINSIZEREL=${CMAKE_C_FLAGS_MINSIZEREL}
                        -DCMAKE_C_FLAGS_RELWITHDEBINFO=${CMAKE_C_FLAGS_RELWITHDEBINFO}
                        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
                        -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
                        -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
                        -DCMAKE_CXX_FLAGS_MINSIZEREL=${CMAKE_CXX_FLAGS_MINSIZEREL}
                        -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
                        -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
)
file(MAKE_DIRECTORY ${CAPSTONE_INCLUDE_DIRS})

set(TLSH_GIT_URL      "https://github.com/mrexodia/tlsh.git")
set(TLSH_ROOT         "${CMAKE_BINARY_DIR}/tlsh")
set(TLSH_INCLUDE_DIRS "${TLSH_ROOT}/src/tlsh/include")
set(TLSH_GIT_TAG      "24d5c0b7fa2ed4d77d9c5dd0c7e1cbf4cd31b42f")

set(TLSH_CMAKE_ARGS
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
)

ExternalProject_Add(
    tlsh
    PREFIX              "${TLSH_ROOT}"
    INSTALL_DIR         "${TLSH_ROOT}"
    GIT_REPOSITORY      "${TLSH_GIT_URL}"
    GIT_TAG             "${TLSH_GIT_TAG}"
    GIT_SHALLOW         ON
    CMAKE_ARGS          ${TLSH_CMAKE_ARGS}
)

file(MAKE_DIRECTORY ${TLSH_INCLUDE_DIRS})

set(LIEF_PREFIX       "${CMAKE_BINARY_DIR}/LIEF")
set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")
set(LIEF_GIT_URL      "https://github.com/lief-project/LIEF.git")
set(LIEF_VERSION      "0.12.2")

set(LIEF_CMAKE_ARGS
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
  -DCMAKE_BUILD_TYPE=Release
  -DLIEF_DOC=off
  -DLIEF_PYTHON_API=off
  -DLIEF_EXAMPLES=off
  -DLIEF_PE=on
  -DLIEF_ELF=on
  -DLIEF_MACHO=off
  -DLIEF_OAT=off
  -DLIEF_DEX=off
  -DLIEF_VDEX=off
  -DLIEF_ART=off
  -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
  -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
  -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
)

ExternalProject_Add(LIEF
  PREFIX           ${LIEF_PREFIX}
  GIT_REPOSITORY   ${LIEF_GIT_URL}
  GIT_TAG          ${LIEF_VERSION}
  INSTALL_DIR      ${LIEF_INSTALL_DIR}
  CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
)

file(MAKE_DIRECTORY ${LIEF_INCLUDE_DIRS})
