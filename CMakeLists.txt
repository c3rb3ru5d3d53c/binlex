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

include(ExternalProject)
include(ProcessorCount)
ProcessorCount(N)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.py
     DESTINATION ${CMAKE_BINARY_DIR}
)

find_package(CAPSTONE REQUIRED)
find_package(TLSH REQUIRED)
find_package(LIEF REQUIRED)

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
