set(TLSH_ROOT "${CMAKE_SOURCE_DIR}/deps/build/tlsh")
set(TLSH_INCLUDE_DIRS "${TLSH_ROOT}/src/tlsh/include")
file(MAKE_DIRECTORY ${TLSH_INCLUDE_DIRS})

add_library(tlsh_static STATIC IMPORTED)
set_target_properties(
    tlsh_static PROPERTIES IMPORTED_LOCATION
    ${TLSH_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}tlsh${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(tlsh_static tlsh)

target_include_directories(tlsh_static INTERFACE ${TLSH_INCLUDE_DIRS})

if(WIN32)
    target_compile_definitions(tlsh_static INTERFACE TLSH_WINDOWS)
endif()
