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

option(BUILD_DECOMPILE_EXECUTABLE "Build \"decompile\" executable as used by Ghidra" OFF)
option(BUILD_DECOMPILE_CLI_EXECUTABLE "Build REPL decompiler" ON)
option(BUILD_SLASPECS "Build Sleigh specs for architectures from Ghidra" ON)
option(GENERATE_PARSERS "Re-generate all parsers with Bison/Flex instead of using pre-generated ones" ON)

set(SOURCE_BASE_CXX
		space.cc
		float.cc
		address.cc
		pcoderaw.cc
		translate.cc
		opcodes.cc
		globalcontext.cc)

set(SOURCE_BASE_YACC
		xml.y)

set(SOURCE_DECOMPILER_CXX
	capability.cc
	architecture.cc
	options.cc
	graph.cc
	cover.cc
	block.cc
	cast.cc
	typeop.cc
	database.cc
	cpool.cc
	comment.cc
	fspec.cc
	action.cc
	loadimage.cc
	loadimage_bfd.cc
	varnode.cc
	op.cc
	type.cc
	variable.cc
	varmap.cc
	jumptable.cc
	emulate.cc
	emulateutil.cc
	flow.cc
	userop.cc
	funcdata.cc
	funcdata_block.cc
	funcdata_varnode.cc
	funcdata_op.cc
	pcodeinject.cc
	heritage.cc
	prefersplit.cc
	rangeutil.cc
	ruleaction.cc
	subflow.cc
	blockaction.cc
	merge.cc
	double.cc
	coreaction.cc
	condexe.cc
	override.cc
	dynamic.cc
	crc32.cc
	prettyprint.cc
	printlanguage.cc
	printc.cc
	printjava.cc
	memstate.cc
	opbehavior.cc
	paramid.cc
	transform.cc
	string_ghidra.cc
	stringmanage.cc
)

set(SOURCE_LIBDECOMP_CXX
		libdecomp.cc)

set(SOURCE_GHIDRA_CXX
		ghidra_process.cc
		ghidra_arch.cc
		loadimage_ghidra.cc
		typegrp_ghidra.cc
		database_ghidra.cc
		ghidra_context.cc
		cpool_ghidra.cc
		comment_ghidra.cc
		inject_ghidra.cc
		ghidra_translate.cc)

set(SOURCE_SLEIGH_CXX
		sleigh_arch.cc
		sleigh.cc
		inject_sleigh.cc
		filemanage.cc
		semantics.cc
		slghsymbol.cc
		context.cc
		sleighbase.cc
		slghpatexpress.cc
		slghpattern.cc
		pcodecompile.cc)

set(SOURCE_SLEIGH_YACC
		pcodeparse.y
		grammar.y)

set(SOURCE_CONSOLE_CXX
		consolemain.cc
		interface.cc
		ifacedecomp.cc
		testfunction.cc
		ifaceterm.cc
		callgraph.cc
		raw_arch.cc)

set(SLEIGH_COMPILER_SOURCE_CXX
		slgh_compile.cc
		slgh_compile.hh)

set(SLEIGH_COMPILER_SOURCE_YACC
		slghparse.y)

set(SLEIGH_COMPILER_SOURCE_FLEX
		slghscan.l)

set(DECOMPILER_SOURCE_DIR decompiler/Ghidra/Features/Decompiler/src/decompile/cpp/)

function(prepend_src_dir list_name)
	set(tmp)
	foreach(r ${${list_name}})
		list(APPEND tmp "${DECOMPILER_SOURCE_DIR}/${r}")
	endforeach()
	set(${list_name} "${tmp}" PARENT_SCOPE)
endfunction()

prepend_src_dir(SOURCE_BASE_CXX)
prepend_src_dir(SOURCE_DECOMPILER_CXX)
prepend_src_dir(SOURCE_LIBDECOMP_CXX)
prepend_src_dir(SOURCE_GHIDRA_CXX)
prepend_src_dir(SOURCE_SLEIGH_CXX)
prepend_src_dir(SOURCE_CONSOLE_CXX)
prepend_src_dir(SLEIGH_COMPILER_SOURCE_CXX)


find_package(BISON REQUIRED)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bison")
find_package(FLEX REQUIRED)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/flex")

macro(build_bison OUT_VAR)
	foreach(yacc_file ${ARGN})
		get_filename_component(yacc_name "${yacc_file}" NAME_WE)
		if("${yacc_name}" STREQUAL "slghparse")
			set(yacc_prefix yy)
		else()
			set(yacc_prefix "${yacc_name}")
		endif()
		if(BISON_VERSION VERSION_LESS 2.6)
			set(BISON_COMPILE_FLAGS "--name-prefix=${yacc_prefix}")
		else()
			set(BISON_COMPILE_FLAGS "-Dapi.prefix={${yacc_prefix}}")
		endif()
		BISON_TARGET(${yacc_name}
				"${CMAKE_CURRENT_SOURCE_DIR}/${DECOMPILER_SOURCE_DIR}/${yacc_file}"
				"${CMAKE_CURRENT_BINARY_DIR}/bison/${yacc_name}.cpp"
				COMPILE_FLAGS ${BISON_COMPILE_FLAGS})
		list(APPEND ${OUT_VAR} "${BISON_${yacc_name}_OUTPUTS}")
	endforeach()
endmacro()

build_bison(SOURCE_BASE_CXX ${SOURCE_BASE_YACC})
build_bison(SOURCE_SLEIGH_CXX ${SOURCE_SLEIGH_YACC})
build_bison(SLEIGH_COMPILER_SOURCE_CXX ${SLEIGH_COMPILER_SOURCE_YACC})

FLEX_TARGET(slghscan "${DECOMPILER_SOURCE_DIR}/${SLEIGH_COMPILER_SOURCE_FLEX}" "${CMAKE_CURRENT_BINARY_DIR}/flex/slghscan.cpp")
list(APPEND SLEIGH_COMPILER_SOURCE_CXX "${CMAKE_CURRENT_BINARY_DIR}/flex/slghscan.cpp")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/flex/slghparse.tab.hh" "#include \"../bison/slghparse.hpp\"")

add_library(ghidra_base STATIC ${SOURCE_BASE_CXX})
target_include_directories(ghidra_base PUBLIC "${DECOMPILER_SOURCE_DIR}")
set_target_properties(ghidra_base PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(ghidra_decompiler STATIC ${SOURCE_DECOMPILER_CXX})
target_link_libraries(ghidra_decompiler PUBLIC -lbfd ghidra_base)
target_include_directories(ghidra_decompiler PUBLIC "${DECOMPILER_SOURCE_DIR}")
set_target_properties(ghidra_decompiler PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(ghidra_sleigh STATIC ${SOURCE_SLEIGH_CXX})
target_link_libraries(ghidra_sleigh PUBLIC ghidra_base)
target_include_directories(ghidra_sleigh PUBLIC "${DECOMPILER_SOURCE_DIR}")
set_target_properties(ghidra_sleigh PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(ghidra_libdecomp STATIC ${SOURCE_LIBDECOMP_CXX})
target_link_libraries(ghidra_libdecomp PUBLIC ghidra_decompiler ghidra_sleigh)
set_target_properties(ghidra_libdecomp PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(ghidra_decompiler_exec ${SOURCE_GHIDRA_CXX})
target_link_libraries(ghidra_decompiler_exec ghidra_decompiler)
set_target_properties(ghidra_decompiler_exec PROPERTIES OUTPUT_NAME decompile)

project(bldec
	VERSION ${GLOBAL_VERSION}
	DESCRIPTION "Binlex Sleigh Decompiler"
)
add_executable(bldec ${SOURCE_CONSOLE_CXX})
target_link_libraries(bldec ghidra_libdecomp)
set_target_properties(bldec PROPERTIES OUTPUT_NAME bldec)

add_executable(sleighc ${SLEIGH_COMPILER_SOURCE_CXX})

target_link_libraries(sleighc ghidra_sleigh)

target_include_directories(sleighc PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/flex")

file(GLOB_RECURSE SLASPEC_FILES "decompiler/Ghidra/Processors/*.slaspec")
file(GLOB_RECURSE CPEC_FILES "decompiler/Ghidra/Processors/*.cspec")
file(GLOB_RECURSE LDEFS_FILES "decompiler/Ghidra/Processors/*.ldefs")
file(GLOB_RECURSE PSPEC_FILES "decompiler/Ghidra/Processors/*.pspec")
set(SLAFILES "")
set(SLEIGH_BASE "${CMAKE_CURRENT_BINARY_DIR}/sleigh")
file(MAKE_DIRECTORY "${SLEIGH_BASE}")
foreach(slaspec ${SLASPEC_FILES})
	get_filename_component(sleigh_name "${slaspec}" NAME_WE)
	get_filename_component(sleigh_dir "${slaspec}" DIRECTORY)
	set(sla_file "${SLEIGH_BASE}/${sleigh_name}.sla")
	add_custom_command(OUTPUT "${sla_file}"
			COMMAND sleighc "${slaspec}" "${sla_file}"
			MAIN_DEPENDENCY "${slaspec}"
			WORKING_DIRECTORY "${sleigh_dir}"
			DEPENDS sleighc)
	list(APPEND SLAFILES "${sla_file}")
endforeach()
add_custom_target(sla ALL DEPENDS ${SLAFILES})

add_library(binlex SHARED
    src/args.cpp
    src/raw.cpp
    src/common.cpp
    src/blelf.cpp
    src/pe.cpp
    src/decompiler.cpp
    #src/pe_rev.cpp
    src/sha256.c
)

set_target_properties(binlex PROPERTIES SOVERSION ${GLOBAL_VERSION})

add_library(binlex::library ALIAS binlex)

target_include_directories(binlex
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include/
		${PROJECT_SOURCE_DIR}/decompiler/Ghidra/Features/Decompiler/src/decompile/cpp/
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
		-lbfd
		ghidra_base
		ghidra_libdecomp
		ghidra_decompiler
		ghidra_sleigh
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
        ${PROJECT_SOURCE_DIR}/include/
		${PROJECT_SOURCE_DIR}//decompiler/Ghidra/Features/Decompiler/src/decompile/cpp/
)

install(TARGETS blyara DESTINATION bin)

add_custom_target(uninstall
    "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
)

set(CPACK_GENERATOR DEB RPM TGZ)
set(CPACK_PACKAGE_NAME binlex)
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
set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcapstone-dev")
include (CPack)