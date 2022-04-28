#include <iostream>
#include <memory>
#include <set>
#include "common.h"

#ifndef FILE_H
#define FILE_H

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
	/*
	  Function will calculate all the hashes for the complete file.

	  @param file_path: path to the file
	*/
	void CalculateFileHashes(char *file_path);
    };
};

#endif
