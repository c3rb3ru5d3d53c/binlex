#include <ctype.h>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>
#include "common.h"

using namespace binlex;

// Global Arguments
Args g_args;

void print_data(string title, void *data, uint32_t size){
    if (g_args.options.debug){
        uint32_t i;
        uint32_t counter = 0;
        cerr << "Hexdump: " << title;
        for (i = 0; i < size; i++) {
            if (counter % 16 == 0) { cerr << endl; }
            cerr << hex << setfill('0') << setw(2) << (uint32_t)((uint8_t *)data)[i] << " ";
            ++counter;
        }
        cerr << endl;
    }
}

string Common::GetTLSH(const uint8_t *data, size_t len){
    Tlsh tlsh;
    tlsh.update(data, len);
    tlsh.final();
    string result = "T1" + string(tlsh.getHash());
    if (result == "T1"){
        return "";
    }
    return result;
}

string Common::GetFileTLSH(const char *file_path){
    FILE *inp;
    uint8_t buf[8192];
    Tlsh tlsh;
    size_t bread;
    string ret;
    inp = fopen(file_path, "rb");
    if(!inp){
	    throw std::runtime_error(strerror(errno));
    }
    while((bread = fread(buf, 1, sizeof(buf), inp)) > 0){
	    tlsh.update(buf, bread);
    }
    if(errno != 0) {
	    throw std::runtime_error(strerror(errno));
    }
    tlsh.final();
    fclose(inp);
    ret = tlsh.getHash();
    return ret;
}

string Common::GetFileSHA256(char *file_path){
    FILE *inp;
    SHA256_CTX ctx;
    uint8_t buf[8192];
    size_t bread;
    uint8_t hash[SHA256_BLOCK_SIZE];
    inp = fopen(file_path, "rb");
    if(!inp){
	    throw std::runtime_error(strerror(errno));
    }
    sha256_init(&ctx);
    while((bread = fread(buf, 1, sizeof(buf), inp)) > 0){
	    sha256_update(&ctx, buf, bread);
    }
    if(errno != 0) {
	    throw std::runtime_error(strerror(errno));
    }
    sha256_final(&ctx, hash);
    fclose(inp);
    return RemoveSpaces(HexdumpBE(&hash, SHA256_BLOCK_SIZE));
}

string Common::Wildcards(uint count){
    stringstream s;
    s << "";
    for (uint i = 0; i < count; i++){
        s << "?? ";
    }
    return TrimRight(s.str());
}

string Common::GetSHA256(const uint8_t *data, size_t len){
    uint8_t hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
    return RemoveSpaces(HexdumpBE(&hash, SHA256_BLOCK_SIZE));
}

string Common::SHA256(char *trait){
    uint8_t hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (uint8_t *)trait, strlen(trait));
    sha256_final(&ctx, hash);
    return RemoveSpaces(HexdumpBE(&hash, SHA256_BLOCK_SIZE));
}

vector<char> Common::TraitToChar(string trait){
    trait = RemoveSpaces(RemoveWildcards(trait));
    vector<char> bytes;
    for (size_t i = 0; i < trait.length(); i = i + 2){
        const char *s_byte = trait.substr(i, 2).c_str();
        unsigned char byte = (char)strtol(s_byte, NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

float Common::Entropy(string trait){
    vector<char> bytes = TraitToChar(trait);
    float result = 0;
    vector<unsigned long> frequencies(256);
    for (char c : bytes){
        frequencies[static_cast<unsigned char>(c)]++;
    }
    for (auto count : frequencies){
	if(count > 0){
	    float freq = static_cast<float>( count ) / bytes.size();
	    result -= freq * log2(freq);
	}
    }
    return result;
}

string Common::RemoveWildcards(string trait){
    string::iterator end_pos = remove(trait.begin(), trait.end(), '?');
    trait.erase(end_pos, trait.end());
    return trait;
}

uint Common::GetByteSize(string s){
    return RemoveSpaces(s).length() / 2;
}

string Common::RemoveSpaces(string s){
    string::iterator end_pos = remove(s.begin(), s.end(), ' ');
    s.erase(end_pos, s.end());
    return s;
}

string Common::WildcardTrait(string trait, string bytes){
    int count = bytes.length();
    for(int i = 0; i < count - 2; i = i + 3){
        bytes.erase(bytes.length() - 3);
        size_t index = trait.find(bytes, 0);
        if (index != string::npos){
            for (size_t j = index; j < trait.length(); j = j + 3){
                trait.replace(j, 2, "??");
            }
            break;
        }
    }
    return TrimRight(trait);
}

string Common::HexdumpBE(const void *data, size_t size){
    stringstream bytes;
    bytes << "";
    const unsigned char *local_pc = (const unsigned char *)data;
    for (size_t i = 0; i < size; i++){
        bytes << hex << setfill('0') << setw(2) << (uint32_t)local_pc[i] << " ";
    }
    return TrimRight(bytes.str());
}

string Common::TraitToTLSH(string trait){
    const vector<uint8_t> data = TraitToData(trait);
    if (data.size() < 50){
        return "";
    }
    return GetTLSH((uint8_t *)&data[0], data.size());
}

vector<uint8_t> Common::TraitToData(string trait){
    trait = RemoveSpaces(RemoveWildcards(trait));
    vector<uint8_t> bytes;
    for (size_t i = 0; i < trait.length(); i = i + 2){
        const char *s_byte = trait.substr(i, 2).c_str();
        unsigned char byte = (char)strtol(s_byte, NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

string Common::TrimRight(const string &s){
    const string whitespace = " \n\r\t\f\v";
    size_t end = s.find_last_not_of(whitespace);
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

void Common::Hexdump(const char * desc, const void * addr, const int len){
    int i;
    unsigned char buff[17];
    const unsigned char * pc = (const unsigned char *)addr;
    if (desc != NULL)
        printf ("%s:\n", desc);
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    else if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }
        printf (" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    printf ("  %s\n", buff);
}

TimedCode::TimedCode(const char *tag) {
    print_tag = tag;
    start = std::chrono::steady_clock::now();
}

void TimedCode::Print() {
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

    int64_t start_time = std::chrono::time_point_cast<std::chrono::microseconds>(start).time_since_epoch().count();
    int64_t end_time = std::chrono::time_point_cast<std::chrono::microseconds>(end).time_since_epoch().count();

    int64_t diff = end_time - start_time;
    int64_t diff_s = diff / 1000000;
    int64_t diff_ms = diff / 1000 - diff_s * 1000;
    int64_t diff_us = diff - diff_s * 1000000 - diff_ms * 1000;

    cerr << "TimedCode: '" << print_tag << "': " << diff_s  << " s "
         << diff_ms << " ms " << diff_us << " us" << endl;
}
