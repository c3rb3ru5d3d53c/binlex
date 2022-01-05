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

add_library(binlex SHARED
    src/args.cpp
    src/raw.cpp
    src/common.cpp
    src/blelf.cpp
    src/decompiler.cpp
    src/pe.cpp
    src/sha256.c
)

set_target_properties(binlex PROPERTIES SOVERSION ${GLOBAL_VERSION})

add_library(binlex::library ALIAS binlex)

target_include_directories(binlex
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

add_executable(binlex-bin
    src/binlex.cpp
)

target_link_libraries(binlex-bin
    PRIVATE
        binlex::library
    PUBLIC
        -lcapstone
        -lm
        -lpthread
        -lLIEF
)

set_target_properties(binlex-bin
    PROPERTIES OUTPUT_NAME binlex
)

install(TARGETS binlex-bin DESTINATION bin)

install(TARGETS binlex
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

project(blyara
    VERSION ${GLOBAL_VERSION}
    DESCRIPTION "A Binlex Yara Generation Utility"
)

set(SOURCES_BLYARA
    src/blyara.cpp
)

add_executable(blyara ${SOURCES_BLYARA})

target_link_libraries(blyara -lm)

target_include_directories(blyara
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
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
            -lcapstone
            -lm
            -lpthread
            -lLIEF
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
# Generates Debian Binary Package
SET(CPACK_GENERATOR DEB RPM)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Binary Genetic Traits Lexer Utilities and C++ Library"
    CACHE STRING "Binary Genetic Traits Lexer Utilities and C++ Library"
)
set(CPACK_RESOURCE_FILE_LICENSE "")
set(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "@c3rb3ru5d3d53c")
set(CPACK_PACKAGE_CONTACT "c3rb3ru5d3d53c@protonmail.com")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_PACKAGE_FILE_NAME "binlex-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcapstone-dev")
# Generates release tarball
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
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${CPACK_SOURCE_IGNORE_FILES}"
)

include (CPack)
