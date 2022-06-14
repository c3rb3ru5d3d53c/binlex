#ifndef FILE_H
#define FILE_H

#include <iostream>
#include <memory>
#include <set>
#ifndef _WIN32
#include <unistd.h>
#endif // _WIN32
#include <string.h>
#include "common.h"

using namespace std;

namespace binlex {
    class File : public Common{
		/**
		 * This class holds data and methods common to files.
		 */
		public:
			BINARY_ARCH binary_arch = BINARY_ARCH_UNKNOWN;
			BINARY_MODE binary_mode = BINARY_MODE_UNKNOWN;
			BINARY_TYPE binary_type = BINARY_TYPE_UNKNOWN;
			string sha256;
			string tlsh;
			struct Section {
				uint offset;
				int size;
				void *data;
				set<uint64_t> functions;
			};
			struct Section sections[BINARY_MAX_SECTIONS];
            uint32_t total_exec_sections = 0;
			/**
			 * This method manually sets the binary architecture and its mode.
			 * @param arch BINARY_ARCH
			 * @param mode BINARY_MODE
			 * @return bool
			 */
			bool SetArchitecture(BINARY_ARCH arch, BINARY_MODE mode);
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
