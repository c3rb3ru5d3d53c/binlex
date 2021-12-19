cmake_minimum_required(VERSION 3.5)

set(GLOBAL_VERSION 1.1.1)

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
    src/pe.cpp
    src/decompiler.cpp
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

target_link_libraries(blyara -lcapstone -lm)

target_include_directories(blyara
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

install(TARGETS blyara DESTINATION bin)

add_custom_target(uninstall
    "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
)
