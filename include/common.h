#include <iostream>
#include <vector>

#ifndef COMMON_H
#define COMMON_H

using namespace std;

class Common{
    public:
        string SHA256(const char *trait);
        vector<char> TraitToChar(string trait);
        string RemoveWildcards(string trait);
        uint GetByteSize(string s);
        string RemoveSpaces(string s);
        string WildcardTrait(string trait, string bytes);
        string TrimRight(const std::string &s);
        string HexdumpBE(const void *data, size_t size);
        void Hexdump(const char * desc, const void * addr, const int len);
};

#endif
