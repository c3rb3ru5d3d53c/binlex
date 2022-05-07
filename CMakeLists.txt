cmake_minimum_required(VERSION 3.5)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 1)
set(VERSION_PATCH 1)
set(GLOBAL_VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

project(binlex
    VERSION ${GLOBAL_VERSION}
    DESCRIPTION "A Binary Genetic Traits Lexer and C++ Library"
)

if(MSVC)
    add_definitions(-D_WIN32=1)
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
endif()

include(ExternalProject)
include(ProcessorCount)

ProcessorCount(N)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.py
     DESTINATION ${CMAKE_BINARY_DIR})

set(CAPSTONE_ROOT    "${CMAKE_BINARY_DIR}/capstone/")
set(CAPSTONE_INCLUDE_DIRS "${CAPSTONE_ROOT}/include/")
set(CAPSTONE_GIT_URL "https://github.com/capstone-engine/capstone.git")
set(CAPSTONE_GIT_TAG 4.0.2)

ExternalProject_Add(
    capstone
    PREFIX              "${CAPSTONE_ROOT}"
    INSTALL_DIR         "${CAPSTONE_ROOT}"
    GIT_REPOSITORY      "${CAPSTONE_GIT_URL}"
    GIT_TAG             "${CAPSTONE_GIT_TAG}"
    GIT_SHALLOW         ON
    BUILD_COMMAND make -j${N}
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
set_target_properties(
    capstone_static PROPERTIES IMPORTED_LOCATION
    ${CAPSTONE_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(capstone_static capstone)

set(TLSH_GIT_URL "https://github.com/trendmicro/tlsh.git")
set(TLSH_ROOT    "${CMAKE_BINARY_DIR}/tlsh/")
set(TLSH_INCLUDE_DIRS "${TLSH_ROOT}/src/tlsh/include/")
set(TLSH_GIT_TAG 7c676d32b252c84cf3a540eb5438c315006d68de)

set(TLSH_CMAKE_ARGS
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
  -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
  -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
  -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
)

ExternalProject_Add(
    tlsh
    PREFIX              "${TLSH_ROOT}"
    INSTALL_DIR         "${TLSH_ROOT}"
    GIT_REPOSITORY      "${TLSH_GIT_URL}"
    GIT_TAG             "${TLSH_GIT_TAG}"
    BUILD_COMMAND make -j${N}
    INSTALL_COMMAND ""
    CMAKE_ARGS ${TLSH_CMAKE_ARGS}
)

add_library(tlsh_static STATIC IMPORTED)
set_target_properties(
    tlsh_static PROPERTIES IMPORTED_LOCATION
    ${TLSH_ROOT}/src/tlsh/lib/${CMAKE_STATIC_LIBRARY_PREFIX}tlsh${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(tlsh_static tlsh)

set(LIEF_PREFIX       "${CMAKE_BINARY_DIR}/LIEF/")
set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include/")

set(LIB_LIEF ${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX})

set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

set(LIEF_VERSION 0.11.5)

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

if(MSVC)
  list(APPEND ${LIEF_CMAKE_ARGS} -DLIEF_USE_CRT_RELEASE=MT)
endif()

# -DCMAKE_BUILD_TYPE=Release

ExternalProject_Add(LIEF
  PREFIX           ${LIEF_PREFIX}
  GIT_REPOSITORY   ${LIEF_GIT_URL}
  GIT_TAG          ${LIEF_VERSION}
  BUILD_COMMAND make -j${N}
  INSTALL_DIR      ${LIEF_INSTALL_DIR}
  CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
)

add_library(lief_static STATIC IMPORTED)
set_target_properties(
    lief_static PROPERTIES IMPORTED_LOCATION
    ${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(lief_static LIEF)

add_library(binlex SHARED
    src/args.cpp
    src/raw.cpp
    src/common.cpp
    src/blelf.cpp
    src/auto.cpp
    src/decompilerbase.cpp
    src/decompiler.cpp
    src/pe-dotnet.cpp
    src/cil.cpp
    src/pe.cpp
    src/file.cpp
    src/sha256.c
)

add_dependencies(binlex LIEF)
add_dependencies(binlex capstone)

set_target_properties(binlex PROPERTIES SOVERSION ${GLOBAL_VERSION})

target_link_libraries(binlex
    PUBLIC
        lief_static
        capstone_static
        tlsh_static
        -lpthread
)

set_target_properties(binlex
	PROPERTIES COMPILE_FLAGS
	-DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
	-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
	-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
)

add_library(binlex::library ALIAS binlex)

if(MSVC)
  target_compile_options(binlex PUBLIC /FIiso646.h)
  set_property(TARGET binlex PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

target_include_directories(binlex
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${LIEF_INCLUDE_DIRS}
        ${CAPSTONE_INCLUDE_DIRS}
        ${TLSH_INCLUDE_DIRS}
)

add_executable(binlex-bin
    src/binlex.cpp
)

add_dependencies(binlex-bin LIEF)
add_dependencies(binlex-bin capstone)

target_link_libraries(binlex-bin
    PRIVATE
        binlex::library
)

set_target_properties(binlex-bin
    PROPERTIES OUTPUT_NAME binlex
)

install(TARGETS binlex-bin DESTINATION bin)

install(TARGETS binlex
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(SOURCES_BLYARA
    src/blyara.cpp
)

add_executable(blyara ${SOURCES_BLYARA})

target_include_directories(blyara
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${LIEF_INCLUDE_DIRS}
        ${CAPSTONE_INCLUDE_DIRS}
        ${TLSH_INCLUDE_DIRS}
)

install(TARGETS blyara DESTINATION bin)

if (BUILD_PYTHON_BINDINGS)
    include_directories(
        include/
        ${pybind11_INCLUDE_DIRS}
    )
    link_directories(src/)
    add_subdirectory(bindings/python/pybind11/)
    pybind11_add_module(pybinlex
        SHARED
        bindings/python/blelf.cpp
        bindings/python/common.cpp
        bindings/python/file.cpp
        bindings/python/pe.cpp
        bindings/python/raw.cpp
        bindings/python/decompiler.cpp
        bindings/python/pybinlex.cpp
    )
    target_link_libraries(pybinlex
        PRIVATE
            pybind11::module
            binlex::library
        PUBLIC
            capstone_static
            -lpthread
            lief_static
            tlsh_static
            ${pybind11_LIBRARIES}
    )
endif()

add_custom_target(uninstall
    "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
)

set(CPACK_PACKAGE_NAME binlex)
string(CONCAT PKG_NAME "${CPACK_PACKAGE_NAME}"
                       "-"
                       "${VERSION_MAJOR}"
                       "."
                       "${VERSION_MINOR}"
                       "."
                       "${VERSION_PATCH}"
)

SET(CPACK_GENERATOR DEB RPM)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Binary Genetic Traits Lexer Utilities and C++ Library"
    CACHE STRING "Binary Genetic Traits Lexer Utilities and C++ Library"
)
set(CPACK_RESOURCE_FILE_LICENSE "")
set(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "@c3rb3ru5d3d53c")
set(CPACK_PACKAGE_CONTACT "c3rb3ru5d3d53c@gmail.com")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_PACKAGE_FILE_NAME "${PKG_NAME}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libtlsh-dev")

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

include (CPack)
