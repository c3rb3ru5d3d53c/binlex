#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <LIEF/PE.hpp>
#include "pe_rev.h"
#include "common.h"

using namespace std;
using namespace binlex;
using namespace LIEF::PE;

PEREV::PEREV(){
    for (int i = 0; i < PEREV_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        sections[i].data = NULL;
    }
}

bool PEREV::ReadFile(char *file_path){
    fd = fopen(file_path, "rb");
    if (fd == NULL){
		fprintf(stderr, "[x] failed to open %s\n", file_path);
		return false;
	}
    binary = Parser::parse(file_path);
    if (binary->has_exports()){
        Export exports = binary->get_export();
        it_export_entries export_entries = exports.entries();
        for (auto it = export_entries.begin(); it != export_entries.end(); it++){
            cout << it->name() << endl;
            function_rvas.insert(it->address());
        }
    }
    uint index = 0;
    it_const_sections it_sections = binary->sections();
    for (auto it = it_sections.begin(); it != it_sections.end(); it++){
        if (it->characteristics() & 0x20000000){
            sections[index].offset = it->offset();
            sections[index].size = it->sizeof_raw_data();
            sections[index].data = malloc(sections[index].size);
            memset(sections[index].data, 0, sections[index].size);
            fseek(fd, sections[index].offset, SEEK_SET);
            fread(sections[index].data, sections[index].size, 1, fd);
            Hexdump("asdf", sections[index].data, sections[index].size);
        }
        index++;
    }
    return true;
}

PEREV::~PEREV(){
    if (fd != NULL){
        fclose(fd);
    }
    for (int i = 0; i < PEREV_MAX_SECTIONS; i++){
        sections[i].offset = 0;
        sections[i].size = 0;
        if (sections[i].data != NULL){
            free(sections[i].data);
        }
    }
}