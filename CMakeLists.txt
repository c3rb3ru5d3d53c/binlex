cmake_minimum_required(VERSION 3.5)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

set(CMAKE_INSTALL_INCLUDEDIR include)

option(BUILD_PYTHON_BINDINGS "Build python bindings (pybinlex)" OFF)

# Linking a pybind11 module with a static library without -fPIC will error
if(BUILD_PYTHON_BINDINGS)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    if(NOT PYBIND11_PYTHON_VERSION)
        execute_process(
            COMMAND python3 -c "import platform; print(platform.python_version(), end='')"
            OUTPUT_VARIABLE PYTHON_VERSION)
        set(PYBIND11_PYTHON_VERSION "${PYTHON_VERSION}")
    endif()
endif()

if(WIN32)
    # TODO: this can be supported with https://cmake.org/cmake/help/latest/module/GenerateExportHeader.html
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
else()
    # NOTE: mutually exclusive with python bindings
    option(BUILD_SHARED_LIBS "Build binlex as a shared library (linux only)" OFF)
endif()

# Enable folder support
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

project(binlex
    VERSION 1.1.1
    DESCRIPTION "A Binary Genetic Traits Lexer and C++ Library"
)

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()

if(MSVC)
    add_definitions(-DNOMINMAX)
    # HACK: be compatible with the ExternalProject's that are built in Release mode
    string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
endif()

include(ExternalProject)
include(ProcessorCount)
ProcessorCount(N)

if(CMAKE_GENERATOR MATCHES "Visual Studio")
    # https://stackoverflow.com/a/70102570/1806760
    set(EXTERNAL_BUILD_COMMAND "")
else()
    set(EXTERNAL_BUILD_COMMAND cmake --build . --parallel ${N})
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.py
     DESTINATION ${CMAKE_BINARY_DIR}
)

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
    BUILD_COMMAND       ${EXTERNAL_BUILD_COMMAND}
    CMAKE_ARGS          -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
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

add_library(capstone_static STATIC IMPORTED)
set_target_properties(capstone_static PROPERTIES
    IMPORTED_LOCATION ${CAPSTONE_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(capstone_static capstone)
file(MAKE_DIRECTORY ${CAPSTONE_INCLUDE_DIRS})
target_include_directories(capstone_static INTERFACE ${CAPSTONE_INCLUDE_DIRS})

set(TLSH_GIT_URL      "https://github.com/mrexodia/tlsh.git")
set(TLSH_ROOT         "${CMAKE_BINARY_DIR}/tlsh/")
set(TLSH_INCLUDE_DIRS "${TLSH_ROOT}/src/tlsh/include/")
set(TLSH_GIT_TAG      "24d5c0b7fa2ed4d77d9c5dd0c7e1cbf4cd31b42f")

set(TLSH_CMAKE_ARGS
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
    BUILD_COMMAND       ${EXTERNAL_BUILD_COMMAND}
    CMAKE_ARGS          ${TLSH_CMAKE_ARGS}
)

add_library(tlsh_static STATIC IMPORTED)
set_target_properties(
    tlsh_static PROPERTIES IMPORTED_LOCATION
    ${TLSH_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}tlsh${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(tlsh_static tlsh)
if(WIN32)
    target_compile_definitions(tlsh_static INTERFACE TLSH_WINDOWS)
endif()
file(MAKE_DIRECTORY ${TLSH_INCLUDE_DIRS})
target_include_directories(tlsh_static INTERFACE ${TLSH_INCLUDE_DIRS})

set(LIEF_PREFIX       "${CMAKE_BINARY_DIR}/LIEF/")
set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include/")
set(LIEF_GIT_URL      "https://github.com/lief-project/LIEF.git")
set(LIEF_VERSION      "0.12.2")

set(LIEF_CMAKE_ARGS
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
  BUILD_COMMAND    ${EXTERNAL_BUILD_COMMAND}
  INSTALL_DIR      ${LIEF_INSTALL_DIR}
  CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
)

add_library(lief_static STATIC IMPORTED)
set_target_properties(lief_static PROPERTIES
    IMPORTED_LOCATION ${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(lief_static LIEF)
file(MAKE_DIRECTORY ${LIEF_INCLUDE_DIRS})
target_include_directories(lief_static INTERFACE ${LIEF_INCLUDE_DIRS})

add_library(binlex
    src/args.cpp
    src/raw.cpp
    src/common.cpp
    src/blelf.cpp
    src/auto.cpp
    src/disassemblerbase.cpp
    src/disassembler.cpp
    src/pe-dotnet.cpp
    src/cil.cpp
    src/pe.cpp
    src/file.cpp
    src/sha256.c
)

set_target_properties(binlex PROPERTIES SOVERSION ${PROJECT_VERSION})

find_package(Threads REQUIRED)

target_link_libraries(binlex PUBLIC
    lief_static
    capstone_static
    tlsh_static
    Threads::Threads
)

target_compile_features(binlex PUBLIC cxx_std_11)

add_library(binlex::library ALIAS binlex)

if(MSVC)
    target_compile_options(binlex PUBLIC /FIiso646.h)
endif()

target_include_directories(binlex PUBLIC include)

add_executable(binlex-bin
    src/binlex.cpp
)

target_link_libraries(binlex-bin PRIVATE
    binlex::library
)

set_target_properties(binlex-bin PROPERTIES
    OUTPUT_NAME binlex
    ARCHIVE_OUTPUT_NAME binlex-bin # TODO: the executable shouldn't have any exports
    PDB_NAME binlex-bin
)

install(TARGETS binlex-bin DESTINATION bin)

install(TARGETS binlex
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(SOURCES_BLYARA
    src/blyara.cpp
)

add_executable(blyara ${SOURCES_BLYARA})

target_include_directories(blyara PRIVATE include)

target_compile_features(blyara PRIVATE cxx_std_11)

install(TARGETS blyara DESTINATION bin)

if (BUILD_PYTHON_BINDINGS)
    add_subdirectory(bindings/python/pybind11)
    pybind11_add_module(pybinlex MODULE
        bindings/python/blelf.cpp
        bindings/python/common.cpp
        bindings/python/file.cpp
        bindings/python/pe.cpp
        bindings/python/raw.cpp
        bindings/python/disassembler.cpp
        bindings/python/pybinlex.cpp
    )
    target_link_libraries(pybinlex PRIVATE
        binlex::library
    )
    install(TARGETS pybinlex DESTINATION bin)
endif()

add_custom_target(uninstall
    "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
)

set(CPACK_PACKAGE_NAME binlex)
set(PKG_NAME "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${PKG_NAME}")
set(CPACK_RESOURCE_FILE_LICENSE "")
set(CPACK_PACKAGE_CONTACT "c3rb3ru5d3d53c@gmail.com")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

if (UNIX AND NOT APPLE)
    set(CPACK_GENERATOR DEB RPM)
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "@c3rb3ru5d3d53c")
    set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
endif()

if (APPLE)
    set(CPACK_GENERATOR DragNDrop)
endif()

if (WIN32)
    set(CPACK_GENERATOR NSIS64)
    set(CPACK_NSIS_MODIFY_PATH ON)
    set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/c3rb3ru5d3d53c/binlex")
endif()

set(CPACK_SOURCE_GENERATOR TGZ ZIP)
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${PKG_NAME}")
set(CPACK_SOURCE_IGNORE_FILES
    "\.git/"
    ".*~$"
    "\.gitmodules"
    "\.gitattributes"
    "\.appveyor.yml"
    "docker/data/"
    "samples/"
    "tests/"
    "pybinlex.egg-info/"
    "*.whl"
    "*.so"
    "venv/"
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${CPACK_SOURCE_IGNORE_FILES}"
)

include(CPack)
