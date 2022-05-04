#include "pe-dotnet.h"

using namespace binlex;
using namespace std;
using namespace dotnet;


TableEntry* TableEntry::TableEntryFactory(uint8_t entry_type) {
    switch(entry_type){
        case MODULE:
            return new ModuleEntry();
        case TYPE_REF:
            return new TypeRefEntry();
        case TYPE_DEF:
            return new TypeDefEntry();
        case FIELD_PTR:
            return new FieldPtrEntry();
        case FIELD:
            return new FieldEntry();
        case METHOD_PTR:
            return new MethodPtrEntry();
        case METHOD_DEF:
            return new MethodDefEntry();
    }
    return NULL;
};


uint32_t Cor20MetadataTable::ParseTablePointers(char *&buffer) {
    uint32_t *buffer_aux;
    uint32_t read_bytes;
    uint8_t i, j;

    buffer_aux = (uint32_t *)buffer;
    j = 0;
    read_bytes = 0;
    for (uint16_t i = 0; i < 8 * 8; i++) {
        if ( (mask_valid >> i) & 1 ) {
            table_entries[i] = buffer_aux[j++];
            read_bytes += 4;
        }
    }
    return read_bytes;
}

uint32_t Cor20MetadataTable::ParseTables(char *&buffer) {
    char *buff_aux;
    TableEntry* entry;

    buff_aux = buffer;
    for (size_t i = 0; i < 8 * 8; i++)
    {
        if (table_entries[i] == 0) continue;
        for (size_t j = 0; j < table_entries[i]; j++) {
            entry = TableEntry().TableEntryFactory(i);
            if (entry == NULL) continue;
            buff_aux += entry->Parse(buff_aux, heap_sizes, table_entries);
            tables[i].push_back(entry);
        }
        // We don't need to parse the rest of the .NET at this moment to get the IL code
        // so simply stop here parsing process
        if ( i > METHOD_DEF ) break;
    }
    return (uint32_t)(buff_aux - buffer);
}

Cor20MetadataTable::~Cor20MetadataTable() {
    for (size_t i = 0; i < 8 * 8; i++){
        if (table_entries[i] == 0) continue;
        for (size_t j = 0; j < tables[i].size(); j++){
            if (tables[i][j] != NULL){
                delete tables[i][j];
            }
        }
    }
}

bool DOTNET::Parse(){
    if (ParseCor20Header() == false){
        return false;
    }
    if (ParseCor20StorageSignature() == false){
        return false;
    }
    if (ParseCor20StorageHeader() == false){
        return false;
    }
    if (ParseCor20StreamsHeader() == false){
        return false;
    }
    if (ParseCor20MetadataStream() == false){
        return false;
    }
    return true;
}

bool DOTNET::ParseCor20Header(){
    DataDirectory clr_data_directory;
    vector<uint8_t> raw_data;

    if (binary->has(DATA_DIRECTORY::CLR_RUNTIME_HEADER) == false) return false;

    clr_data_directory = binary->data_directory(DATA_DIRECTORY::CLR_RUNTIME_HEADER);
    raw_data = binary->get_content_from_virtual_address(clr_data_directory.RVA(),
                                                              clr_data_directory.size());
    memcpy((void *) &cor20_header, raw_data.data(), sizeof(cor20_header));
    return true;
}

bool DOTNET::ParseCor20StorageSignature(){
    vector<uint8_t> raw_data;
    unsigned char* storage_signature;

    raw_data = binary->get_content_from_virtual_address(cor20_header.metadata_rva,
                                                              cor20_header.metadata_size);
    storage_signature = raw_data.data();
    cor20_storage_signature.signature             = *(uint32_t *)(storage_signature + 0);
    cor20_storage_signature.major_version         = *(uint16_t *)(storage_signature + 4);
    cor20_storage_signature.minor_version         = *(uint16_t *)(storage_signature + 6);
    cor20_storage_signature.extra_data            = *(uint32_t *)(storage_signature + 8);
    cor20_storage_signature.version_string_size   = *(uint32_t *)(storage_signature + 12);
    cor20_storage_signature.version_string        = (unsigned char *)malloc(
                                                          cor20_storage_signature.version_string_size);

    if (cor20_storage_signature.version_string == NULL) return false;

    memcpy(cor20_storage_signature.version_string,
           (char*)(storage_signature + 16),
           cor20_storage_signature.version_string_size);
    return true;
}

bool DOTNET::ParseCor20StorageHeader(){
    vector<uint8_t> raw_data;
    unsigned char *storage_signature, *storage_header;
    uint32_t size_of_storage_signature;

    raw_data = binary->get_content_from_virtual_address(cor20_header.metadata_rva, cor20_header.metadata_size);
    storage_signature = raw_data.data();

    size_of_storage_signature = sizeof(cor20_storage_signature) - \
                                sizeof(cor20_storage_signature.version_string) + \
                                cor20_storage_signature.version_string_size;

    storage_header = storage_signature + size_of_storage_signature;

    cor20_storage_header.flags             = *(uint8_t *)(storage_header + 0);
    cor20_storage_header.pad               = *(uint8_t *)(storage_header + 1);
    cor20_storage_header.number_of_streams = *(uint16_t *)(storage_header + 2);
    return true;
}

bool DOTNET::ParseCor20StreamsHeader(){
    vector<uint8_t> raw_data;
    unsigned char *storage_signature, *storage_header, *streams_header, *streams_header_aux;
    uint32_t size_of_storage_signature;

    raw_data = binary->get_content_from_virtual_address(cor20_header.metadata_rva, cor20_header.metadata_size);
    storage_signature = raw_data.data();

    size_of_storage_signature = sizeof(cor20_storage_signature) - \
                                sizeof(cor20_storage_signature.version_string) + \
                                cor20_storage_signature.version_string_size;

    storage_header = storage_signature + size_of_storage_signature;

    streams_header = storage_header + sizeof(cor20_storage_header);
    streams_header_aux = streams_header;
    StreamsHeader = (dotnet::COR20_STREAM_HEADER **)calloc(sizeof(dotnet::COR20_STREAM_HEADER *), cor20_storage_header.number_of_streams);
    for (uint16_t i = 0;
         i < cor20_storage_header.number_of_streams;
         i++)
    {
        uint32_t offset = *(uint32_t *)(streams_header_aux); streams_header_aux += 4;
        uint32_t size = *(uint32_t *)(streams_header_aux); streams_header_aux += 4;
        char *name = (char *)streams_header_aux;

        StreamsHeader[i] = (dotnet::COR20_STREAM_HEADER *)calloc(sizeof(dotnet::COR20_STREAM_HEADER), 1);
        StreamsHeader[i]->offset = offset;
        StreamsHeader[i]->size = size;
        StreamsHeader[i]->name = (char *)calloc(sizeof(char), strlen(name) + 1);
        memcpy(StreamsHeader[i]->name, name, strlen(name));
        size_t name_size = strlen(name);
        size_t boundary = 4 - (name_size % 4);
        streams_header_aux += name_size + boundary;
    }
    return true;
}

bool DOTNET::ParseCor20MetadataStream()
{
    vector<uint8_t> raw_data;
    unsigned char *storage_signature, *storage_header, *streams_header, *streams_header_aux;
    uint32_t size_of_storage_signature;
    dotnet::COR20_STREAM_HEADER *stream_metadata_header = NULL;

    raw_data = binary->get_content_from_virtual_address(cor20_header.metadata_rva, cor20_header.metadata_size);
    storage_signature = raw_data.data();

    for (size_t i = 0; i < cor20_storage_header.number_of_streams; i++)
    {
        if (strncmp(StreamsHeader[i]->name, "#~", 2) == 0)
        {
            stream_metadata_header = StreamsHeader[i];
        }
    }
    if (stream_metadata_header == NULL) return false;

    memcpy(&cor20_metadata_table.reserved, storage_signature + stream_metadata_header->offset, 24);
    char *buff = (char *)(storage_signature + stream_metadata_header->offset + 24);
    buff += cor20_metadata_table.ParseTablePointers(buff);
    cor20_metadata_table.ParseTables(buff);

    return true;
}

void DOTNET::ParseSections(){
    size_t num_of_sections;
    uint8_t header, code_offset;
    vector<uint8_t> data;

    num_of_sections = ( cor20_metadata_table.tables[METHOD_DEF].size() < BINARY_MAX_SECTIONS) ? cor20_metadata_table.tables[METHOD_DEF].size() : BINARY_MAX_SECTIONS;
    for (size_t i = 0; i < num_of_sections; i++) {
        MethodDefEntry* mentry = (MethodDefEntry *)cor20_metadata_table.tables[METHOD_DEF][i];
        if (mentry->rva == 0) continue;
        Section section = {};
        section.offset = mentry->rva;

        header = binary->get_content_from_virtual_address(mentry->rva, 1).data()[0];

        // Check header type Tiny or FAT type.
        code_offset = 0;
        if ( (header & 3) == 2){
            // Tiny header
            section.size = header >> 2;
            code_offset = 1;
        } else {
            // FAT header
            uint16_t max_stack = *(uint16_t *)&binary->get_content_from_virtual_address(
                                 mentry->rva + 2,
                                 2)[0];
            uint32_t code_size = *(uint32_t *)&binary->get_content_from_virtual_address(
                                 mentry->rva + 4,
                                 4)[0];
            uint32_t local_var_sig_tok = *(uint32_t *)&binary->get_content_from_virtual_address(
                                 mentry->rva + 8,
                                 4)[0];
            section.size = code_size;
            code_offset = 12;
        }
        section.data = calloc(section.size, 1);
        if (section.data == NULL){
            fprintf(stderr, "[x] cannot allocate memory\n");
        }
        data = binary->get_content_from_virtual_address(section.offset + code_offset, section.size);
        memcpy(section.data, &data[0], section.size);
        _sections.push_back(section);
    }
}

bool DOTNET::ReadVector(const std::vector<uint8_t> &data){
    CalculateFileHashes(data);
    binary = Parser::parse(data);
    if (binary == NULL){
        return false;
    }
    if (mode != binary->header().machine()){
        fprintf(stderr, "[x] incorrect mode for binary architecture\n");
        return false;
    }
    if (IsDotNet() == false) return false;
    if (Parse() == false) return false;
    ParseSections();
    return true;
}

DOTNET::~DOTNET(){
    for (size_t i = 0; i < _sections.size(); i++){
        if (_sections[i].data != NULL){
            free(_sections[i].data);
        }
    }
    _sections.clear();

    if (cor20_storage_signature.version_string != NULL){
        free(cor20_storage_signature.version_string);
    }

    for (size_t i = 0; i < cor20_storage_header.number_of_streams; i++){
        if (StreamsHeader == NULL) break;
        if (StreamsHeader[i] != NULL){
            if (StreamsHeader[i]->name != NULL){
                free(StreamsHeader[i]->name);
            }
            free(StreamsHeader[i]);
        }
    }
    if (StreamsHeader != NULL){
        free(StreamsHeader);
    }
}
