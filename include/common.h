#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <iomanip>
#include <vector>
#include <queue>
#include <set>
#include <map>
#include "args.h"

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif

using std::set;
using std::map;
using std::queue;
using std::set;
using std::vector;
using std::ofstream;
using std::stringstream;
using std::string;
using std::cin;
using std::cout;
using std::cerr;
using std::endl;
using std::hex;
using std::setfill;
using std::setw;

#define BINARY_MAX_SECTIONS 256

#ifdef _WIN32
typedef unsigned int uint;
typedef uint useconds_t;
#endif

extern binlex::Args g_args;

// Debug
#define PRINT_DEBUG(...) {if (g_args.options.debug) fprintf(stderr, __VA_ARGS__); }
#define PRINT_ERROR_AND_EXIT(...) { fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE); }
void print_data(string title, void *data, uint32_t size);
#define PRINT_DATA(title, data, size) { print_data(title, data, size); }

namespace binlex {
    class Common{
        /**
        This class contains methods common to binlex.
        */
        public:
        /**
	    This method takes a (binary) input string and returns its tlsh hash.
	    @param data input string
        @param len length of data
	    @return Returns the tlsh hash of the trait string
	    */
	    BINLEX_EXPORT static string GetTLSH(const uint8_t *data, size_t len);
        /**
	    This method reads a file returns its tlsh hash.
	    @param file_path path to the file to read
	    @return Returns the tlsh hash of the file
	    @throw std::runtime_error if file operation fails
	    */
        BINLEX_EXPORT static string GetFileTLSH(const char *file_path);
        /**
        This method takes an input string and returns its sha256 hash.
        @param trait input string.
        @return Returns the sha256 hash of the trait string
        */
        BINLEX_EXPORT static string SHA256(char *trait);
        /**
        This method reads a file returns its sha256 hash.
        @param file_path path to the file to read
        @return Returns the sha256 hash of the file
        @throw std::runtime_error if file operation fails
        */
        BINLEX_EXPORT static string GetFileSHA256(char *file_path);
        /**
        This method reads a file returns its sha256 hash.
        @param data input string
        @param len length of data
        @return Returns the sha256 hash of the file
        @throw std::runtime_error if file operation fails
        */
        BINLEX_EXPORT static string GetSHA256(const uint8_t *data, size_t len);
        /**
        This method takes an input trait string and returns a char vector of bytes (ignores wildcards).
        @param trait input string.
        @return Returns char vector of bytes
        */
        BINLEX_EXPORT static vector<char> TraitToChar(string trait);
        /**
        This method removes wildcards from a trait string.
        @param trait input trait string.
        @return Returns trait without wildcards
        */
        BINLEX_EXPORT static string RemoveWildcards(string trait);
        /**
        This method gets the size in bytes of a trait string (includes wildcards).
        @param trait input trait string.
        @return Returns uint size of bytes
        */
        BINLEX_EXPORT static uint GetByteSize(string s);
        /**
        This method removes spaces from a string.
        @param s input string
        @return Returns string without spaces
        */
        BINLEX_EXPORT static string RemoveSpaces(string s);
        /**
        This method wildcards byte strings for traits.
        @param trait input trait string
        @param bytes byte string to wildcard
        @return Returns wildcarded trait string
        */
        BINLEX_EXPORT static string WildcardTrait(string trait, string bytes);
        /**
        This method removes whitespace on the right.
        @param s input string
        @return Returns string with whitespace on right trimmed
        */
        BINLEX_EXPORT static string TrimRight(const std::string &s);
        /**
        This method creates a byte string based on a pointer and its size.
        @param data A pointer to the data
        @param size The size of the data to collect
        @return Returns a byte string of the selected data
        */
        BINLEX_EXPORT static string HexdumpBE(const void *data, size_t size);
        /**
        Generate Number of Wildcards
        @param count number of wildcard bytes to create
        @return string
        */
        BINLEX_EXPORT static string Wildcards(uint count);
        BINLEX_EXPORT static string HexdumpMemDisp(uint64_t disp);
        BINLEX_EXPORT static float Entropy(string trait);
        /**
        This method prints hexdump to stdout.
        @param desc A description of the data.
        @param data A pointer to the data
        @param size The size of the data to collect
        */
        BINLEX_EXPORT static void Hexdump(const char * desc, const void * addr, const int len);
    };
}

#endif
