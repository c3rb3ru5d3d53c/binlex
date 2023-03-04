set(LIEF_PREFIX       "${CMAKE_SOURCE_DIR}/deps/build/LIEF")
set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")
file(MAKE_DIRECTORY ${LIEF_INCLUDE_DIRS})

add_library(lief_static STATIC IMPORTED)
set_target_properties(lief_static PROPERTIES
    IMPORTED_LOCATION ${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(lief_static LIEF)
target_include_directories(lief_static INTERFACE ${LIEF_INCLUDE_DIRS})
