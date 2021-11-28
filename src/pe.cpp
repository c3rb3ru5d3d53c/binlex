#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe.h"

Pe::Pe(){
	for (int i = 0; i < PE_MAX_SECTIONS; i++){
		sections[i].size = 0;
		sections[i].offset = 0;
		sections[i].data = NULL;
	}
}

bool Pe::Setup(int input_mode){
	dos_header = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
	coff_header = (PIMAGE_COFF_HEADER)malloc(sizeof(IMAGE_COFF_HEADER));
	section_header = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER));
	switch(input_mode){
		case PE_MODE_X86:
			mode = PE_MODE_X86;
			break;
		case PE_MODE_X86_64:
			mode = PE_MODE_X86_64;
			break;
		default:
			fprintf(stderr, "[x] unsupported elf executable mode\n");
			mode = PE_MODE_UNSET;
			return false;
	}
	return true;
}

bool Pe::is_pe(){
	if (dos_header->e_magic != 23117 ||
		coff_header->Signature != 17744){
		return false;
	}
	return true;
}

bool Pe::ReadFile(char *file_path){
	fd = fopen(file_path, "rb");
	if (fd == NULL){
		fprintf(stderr, "[x] failed to open %s\n", file_path);
		return false;
	}
	fread(dos_header, sizeof(IMAGE_DOS_HEADER), 1, fd);
	fseek(fd, dos_header->e_lfanew, SEEK_SET);
	fread(coff_header, sizeof(IMAGE_COFF_HEADER), 1, fd);
	if (is_pe() == false){
		fprintf(stderr, "[x] %s is not a valid pe file\n", file_path);
		return false;
	}
	if (mode == PE_MODE_X86 && coff_header->Machine != IMAGE_FILE_MACHINE_I386){
		fprintf(stderr, "[x] %s is not a valid x86 pe file\n", file_path);
		return false;
	}
	if (mode == PE_MODE_X86_64 && coff_header->Machine != IMAGE_FILE_MACHINE_AMD64){
		fprintf(stderr, "[x] %s is not a valid x86_64 pe file\n", file_path);
		return false;
	}
	if (mode == PE_MODE_X86 && coff_header->Machine == IMAGE_FILE_MACHINE_I386){
		optional_header_32 = (PIMAGE_OPTIONAL_HEADER_32)malloc(sizeof(IMAGE_OPTIONAL_HEADER_32));
		if (fread(optional_header_32, sizeof(IMAGE_OPTIONAL_HEADER_32), 1, fd) <= 0){
			fprintf(stderr, "[x] failed to read %s optional_header_64\n", file_path);
			return false;
		}
	}
	if (mode == PE_MODE_X86_64 && coff_header->Machine == IMAGE_FILE_MACHINE_AMD64){
		optional_header_64 = (PIMAGE_OPTIONAL_HEADER_64)malloc(sizeof(IMAGE_OPTIONAL_HEADER_64));
		if (fread(optional_header_64, sizeof(IMAGE_OPTIONAL_HEADER_64), 1, fd) <= 0){
			fprintf(stderr, "[x] failed to read %s optional_header_64\n", file_path);
			return false;
		}
	}
	for (int i = 0; i < coff_header->NumberOfSections; i++){
		if (fread(section_header, sizeof(IMAGE_SECTION_HEADER), 1, fd) <= 0){
			fprintf(stderr, "[x] failed to read %s section_header\n", file_path);
			return false;
		}
		if (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE){
			int set = ftell(fd);
			fseek(fd, section_header->PointerToRawData, SEEK_SET);
			sections[i].offset = section_header->PointerToRawData;
			sections[i].size = section_header->SizeOfRawData;
			sections[i].data = malloc(section_header->SizeOfRawData);
			if (sections[i].data == NULL){
				fprintf(stderr, "[x] failed to allocate section memory\n");
				return false;
			}
			memset(sections[i].data, 0, sections[i].size);
			if (fread(sections[i].data, sections[i].size, 1, fd) <= 0){
				fprintf(stderr, "[x] failed to read %s executable section\n", file_path);
				return false;
			}
			fseek(fd, set, SEEK_SET);
		}

	}
	return true;
}

Pe::~Pe(){
	if (dos_header != NULL){
		free(dos_header);
		dos_header = NULL;
	}
	if (coff_header != NULL){
		free(coff_header);
		coff_header = NULL;
	}
	if (optional_header_32 != NULL){
		free(optional_header_32);
		optional_header_32 = NULL;
	}
	if (optional_header_64 != NULL){
		free(optional_header_64);
		optional_header_64 = NULL;
	}
	if (section_header != NULL){
		free(section_header);
		section_header = NULL;
	}
	for (int i = 0; i < PE_MAX_SECTIONS; i++){
		if (sections[i].data != NULL){
			free(sections[i].data);
			sections[i].size = 0;
			sections[i].offset = 0;
			sections[i].data = NULL;
		}
	}
}
