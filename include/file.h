#ifndef FILE_H
#define FILE_H

#include <iostream>
#include <memory>
#include <set>
#include <unistd.h>
#include <string.h>
#include "common.h"

using namespace std;

namespace binlex {
    class File : public Common{
    public:
        string sha256;
        string tlsh;
	struct Section {
	    uint offset;
	    int size;
	    void *data;
	    set<uint64_t> functions;
	};
	bool FileExists(char *file_path);
	/*
	  Function will calculate all the hashes for the complete file.

	  @param file_path: path to the file
	*/
	void CalculateFileHashes(char *file_path);
	/*
	  Function will calculate all the hashes for the complete file.

	  @param data: file data in a vector
	*/
	void CalculateFileHashes(const vector<uint8_t> &data);
        std::vector<uint8_t> ReadFileIntoVector(const char *file_path);
    };
};

#endif
