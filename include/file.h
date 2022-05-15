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
		/**
		 * This class holds data and methods common to files.
		 */
		public:
			int binary_arch = BINARY_ARCH_UNKNOWN;
			int binary_mode = BINARY_MODE_UNKNOWN;
			string sha256;
			string tlsh;
		struct Section {
			uint offset;
			int size;
			void *data;
			set<uint64_t> functions;
		};
		bool SetBinaryArch(int binary_arch);
		bool SetBinaryMode(int binary_mode);
		/**
		 * Function will calculate all the hashes for the complete file.
		 * @param file_path: path to the file
		 */
		void CalculateFileHashes(char *file_path);
		/**
		 ** Function will calculate all the hashes for the complete file.
		 * @param data: file data in a vector
		 */
		void CalculateFileHashes(const vector<uint8_t> &data);
		/**
		 * Read a file into a vector
		 * @param file_path path to the file to read
		 * @return vector containing the bytes of the file
		 * @throws runtime_error if a read error occurs
		 */
		vector<uint8_t> ReadFileIntoVector(const char *file_path);
		/**
		 * Read data from file.
		 * @param file_path path to the file to read from
		 * @return true if reading successful
		 */
		bool ReadFile(const char *file_path);
		/**
		 * Read data from a buffer
		 * @param data pointer to data
		 * @param size size of the buffer
		 * @return true if reading successful
		 */
		bool ReadBuffer(void *data, size_t size);
		/**
		 * Read data from std::vector
		 * @param data pointer to data
		 * @return true if reading successful
		 */
		virtual bool ReadVector(const std::vector<uint8_t> &data) = 0;
    };
};

#endif
