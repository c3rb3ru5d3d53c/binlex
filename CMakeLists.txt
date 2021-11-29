cmake_minimum_required(VERSION 3.5)

project(binlex)

set(SOURCES_BINLEX
    src/binlex.cpp
    src/args.cpp
    src/raw.cpp
    src/common.cpp
    src/blelf.cpp
    src/pe.cpp
    src/decompiler.cpp
    src/decompiler_rev.cpp
)

add_executable(binlex ${SOURCES_BINLEX})

target_link_libraries(binlex -lcapstone -lcrypto -lm)

target_include_directories(binlex
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

project(blyara)

set(SOURCES_BLYARA
    src/blyara.cpp
)

add_executable(blyara ${SOURCES_BLYARA})

target_link_libraries(blyara -lcapstone -lcrypto -lm)

target_include_directories(blyara
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)
