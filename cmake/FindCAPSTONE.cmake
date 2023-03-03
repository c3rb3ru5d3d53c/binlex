set(CAPSTONE_ROOT "${CMAKE_SOURCE_DIR}/deps/build/capstone")
set(CAPSTONE_INCLUDE_DIRS "${CAPSTONE_ROOT}/include")
file(MAKE_DIRECTORY ${CAPSTONE_INCLUDE_DIRS})

add_library(capstone_static STATIC IMPORTED)
set_target_properties(capstone_static PROPERTIES
    IMPORTED_LOCATION ${CAPSTONE_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(capstone_static capstone)

target_include_directories(capstone_static INTERFACE ${CAPSTONE_INCLUDE_DIRS})
