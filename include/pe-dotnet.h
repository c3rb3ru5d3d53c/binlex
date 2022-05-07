#ifndef DOTNET_H
#define DOTNET_H

#include "pe.h"
#include "common.h"
#include <math.h>

#ifdef _WIN32
#define BINLEX_EXPORT __declspec(dllexport)
#else
#define BINLEX_EXPORT
#endif

//#define PE_DOTNET_MAX_SECTIONS 1000

using namespace binlex;

#define	MODULE                 0
#define	TYPE_REF               1
#define	TYPE_DEF               2
#define	FIELD_PTR              3
#define	FIELD                  4
#define	METHOD_PTR             5
#define	METHOD_DEF             6
#define	PARAMPTR               7
#define	PARAM                  8
#define	INTERFACEIMPL          9
#define	MEMBERREF              10
#define	CONSTANT               11
#define	CUSTOMATTRIBUTE        12
#define	FIELDMARSHAL           13
#define	DECLSECURITY           14
#define	CLASSLAYOUT            15
#define	FIELDLAYOUT            16
#define	STANDALONESIG          17
#define	EVENTMAP               18
#define	EVENTPTR               19
#define	EVENT                  20
#define	PROPERTYMAP            21
#define	PROPERTYPTR            22
#define	PROPERTY               23
#define	METHODSEMANTICS        24
#define	METHODIMPL             25
#define	MODULE_REF             26
#define	TYPE_SPEC              27
#define	IMPLMAP                28
#define	FIELDRVA               29
#define	ENCLOG                 30
#define	ENCMAP                 31
#define	ASSEMBLY               32
#define	ASSEMBLYPROCESSOR      33
#define	ASSEMBLYOS             34
#define	ASSEMBLY_REF           35
#define	ASSEMBLYREFPROCESSOR   36
#define	ASSEMBLYREFOS          37
#define	_FILE                  38
#define	EXPORTEDTYPE           39
#define	MANIFESTRESOURCE       40
#define	NESTEDCLASS            41
#define	GENERICPARAM           42
#define	METHODSPEC             43
#define	GENERICPARAMCONSTRAINT 44
#define	DOCUMENT               48
#define	METHODDEBUGINFORMATION 49
#define	LOCALSCOPE             50
#define	LOCALVARIABLE          51
#define	LOCALCONSTANT          52
#define	IMPORTSCOPE            53
#define	STATEMACHINEMETHOD     54
#define	CUSTOMDEBUGINFORMATION 55


namespace dotnet {
    class MethodHeader {};

    class TinyHeader : public MethodHeader {
        uint32_t size;
    };

    class FatHeader : public MethodHeader {
        uint32_t size;
        uint16_t max_stack;
        uint16_t local_var_sig_tok;
    };

    class Method {
        bool tiny_header = false;
        MethodHeader *header;
        vector<char> code;
    };

    class MultiTableIndex {
        private:
            vector<uint8_t> refs = {};
            virtual vector<uint8_t> GetRefs() { return refs; };
            uint32_t MaxTableEntries(uint32_t *table_entries) {
                uint32_t max_entries = 0;
                for (uint8_t i = 0; i < GetRefs().size(); i++) {
                    if (table_entries[GetRefs()[i]] > max_entries) max_entries = table_entries[GetRefs()[i]];
                }
                return max_entries;
            };
        public:
            uint32_t size = 2;
            uint32_t offset = 0;
            uint32_t value = 0;
            uint32_t Parse(char *&buffer, uint32_t *table_entries) {
                uint32_t max_entry_number, needed_bits_for_tag, remaining_bits_for_indexing;
                needed_bits_for_tag = uint32_t(log2(refs.size()) + 1);
                max_entry_number = MaxTableEntries(table_entries);
                remaining_bits_for_indexing = 16 - needed_bits_for_tag;
                if ( pow(2, remaining_bits_for_indexing) < max_entry_number ) {
                    size = 4;
                }
                if (size == 2) offset = *(uint16_t *)buffer ;
                if (size == 4) offset = *(uint32_t *)buffer ;
                return size;
            };
    };

    class ResolutionScopeIndex : public MultiTableIndex {
        private:
            vector<uint8_t> refs = {
                MODULE,
                MODULE_REF,
                ASSEMBLY_REF,
                TYPE_REF
            };
            vector<uint8_t> GetRefs() { return refs; };
    };

    class TypeDefOrRefIndex: public MultiTableIndex {
        private:
            vector<uint8_t> refs = {
                TYPE_DEF,
                TYPE_REF,
                TYPE_SPEC,
            };
            vector<uint8_t> GetRefs() { return refs; };
    };

    class SimpleTableIndex {
        public:
            uint32_t offset = 0;
            uint32_t value = 0;
            uint32_t size = 2;
            uint32_t Parse(char *&buffer) {
                offset = *(uint16_t *)buffer ;
                return size;
            };
    };

    class StringHeapIndex {
        public:
            StringHeapIndex(uint8_t heap_size) { if ( heap_size & 1 ) size = 4; };
            uint32_t offset = 0;
            uint32_t value = 0;
            uint32_t size = 2;
            uint32_t Parse(char *&buffer) {
                if (size == 2) offset = *(uint16_t *)buffer;
                if (size == 4) offset = *(uint32_t *)buffer ;
                return size;
            };
    };

    class GuidHeapIndex {
        public:
            GuidHeapIndex(uint8_t heap_size) { if ( heap_size & 2 ) size = 4; };
            uint32_t offset = 0;
            uint32_t value = 0;
            uint32_t size = 2;
            uint32_t Parse(char *&buffer) {
                if (size == 2) offset = *(uint16_t *)buffer;
                if (size == 4) offset = *(uint32_t *)buffer ;
                return size;
            };
    };

    class BlobHeapIndex {
        public:
            BlobHeapIndex(uint8_t heap_size) { if ( heap_size & 3 ) size = 4; };
            uint32_t offset;
            uint32_t value;
            uint32_t size = 2;
            uint32_t Parse(char *&buffer) {
                if (size == 2) offset = *(uint16_t *)buffer;
                if (size == 4) offset = *(uint32_t *)buffer ;
                return size;
            };
    };

    class TableEntry{
        public:
            virtual uint32_t Parse(char *buff, uint8_t heap_sizes, uint32_t *table_entries){ return 0; };
            static TableEntry* TableEntryFactory(uint8_t entry_type);
            virtual ~TableEntry() { };
    };

    class ModuleEntry: public TableEntry {
        public:
            uint32_t generation;
            StringHeapIndex name = 0;
            GuidHeapIndex mv_id = 0;
            GuidHeapIndex enc_id = 0;
            GuidHeapIndex enc_base_id = 0;
            uint32_t Parse(char *buff, uint8_t heap_sizes, uint32_t *table_entries) {
                char *buff_aux;
                buff_aux = buff;
                memcpy(&generation, buff_aux, 2);
                buff_aux += 2;
                name = StringHeapIndex(heap_sizes);
                buff_aux += name.Parse(buff_aux);
                mv_id = GuidHeapIndex(heap_sizes);
                buff_aux += mv_id.Parse(buff_aux);
                enc_id = GuidHeapIndex(heap_sizes);
                buff_aux += enc_id.Parse(buff_aux);
                enc_base_id = GuidHeapIndex(heap_sizes);
                buff_aux += enc_base_id.Parse(buff_aux);
                return buff_aux - buff;
            };
    };

    class TypeRefEntry: public TableEntry {
        public:
            ResolutionScopeIndex resolution_scope;
            StringHeapIndex name = 0;
            StringHeapIndex name_space = 0;
            uint32_t Parse(char *buff, uint8_t heap_sizes, uint32_t *table_entries) {
                char *buff_aux;
                buff_aux = buff;
                resolution_scope = ResolutionScopeIndex();
                buff_aux += resolution_scope.Parse(buff_aux, table_entries);
                name = StringHeapIndex(heap_sizes);
                buff_aux += name.Parse(buff_aux);
                name_space = StringHeapIndex(heap_sizes);
                buff_aux += name_space.Parse(buff_aux);
                return buff_aux - buff;
            };
    };

    class TypeDefEntry: public TableEntry {
        public:
            uint32_t flags = 0;
            StringHeapIndex name = 0;
            StringHeapIndex name_space = 0;
            TypeDefOrRefIndex extends;
            SimpleTableIndex field_list;
            SimpleTableIndex method_list;
            uint32_t Parse(char *buff, uint8_t heap_sizes, uint32_t *table_entries) {
                char *buff_aux;
                buff_aux = buff;
                flags = *(uint32_t *)buff_aux;
                buff_aux += 4;
                name = StringHeapIndex(heap_sizes);
                buff_aux += name.Parse(buff_aux);
                name_space = StringHeapIndex(heap_sizes);
                buff_aux += name_space.Parse(buff_aux);
                extends = TypeDefOrRefIndex();
                buff_aux += extends.Parse(buff_aux, table_entries);
                field_list = SimpleTableIndex();
                buff_aux += field_list.Parse(buff_aux);
                method_list = SimpleTableIndex();
                buff_aux += method_list.Parse(buff_aux);
                return buff_aux - buff;
            };
    };

    class FieldPtrEntry: public TableEntry {
        public:
            uint16_t ref;
            uint32_t Parse(char *buff, uint8_t heap_sizes, uint32_t *table_entries) {
                ref = *(uint16_t *)buff;
                return 2;
            };
    };

    class FieldEntry: public TableEntry {
        public:
            uint16_t flags;
            StringHeapIndex name = 0;
            BlobHeapIndex signature = 0;
            uint32_t Parse(char *buff, uint8_t heap_sizes, uint32_t *table_entries) {
                char *buff_aux;
                buff_aux = buff;
                flags = *(uint16_t *)buff_aux;
                buff_aux += 2;
                name = StringHeapIndex(heap_sizes);
                buff_aux += name.Parse(buff_aux);
                signature = BlobHeapIndex(heap_sizes);
                buff_aux += signature.Parse(buff_aux);
                return buff_aux - buff;
            };
    };

    class MethodPtrEntry: public TableEntry {
        public:
            uint16_t ref;
            uint32_t Parse(char *buff, uint8_t heap_sizes, uint32_t *table_entries) {
                ref = *(uint16_t *)buff;
                return 2;
            };
    };

    class MethodDefEntry: public TableEntry {
        public:
            uint32_t rva;
            uint16_t impl_flags;
            uint16_t flags;
            StringHeapIndex name = 0;
            BlobHeapIndex signature = 0;
            SimpleTableIndex param_list;
            uint32_t Parse(char *buff, uint8_t heap_sizes, uint32_t *table_entries) {
                char *buff_aux;
                buff_aux = buff;
                rva = *(uint32_t *)buff_aux;
                buff_aux += 4;
                impl_flags = *(uint16_t *)buff_aux;
                buff_aux += 2;
                flags = *(uint16_t *)buff_aux;
                buff_aux += 2;
                name = StringHeapIndex(heap_sizes);
                buff_aux += name.Parse(buff_aux);
                signature = BlobHeapIndex(heap_sizes);
                buff_aux += signature.Parse(buff_aux);
                param_list = SimpleTableIndex();
                buff_aux += param_list.Parse(buff_aux);
                return buff_aux - buff;
            };
    };


    class Cor20MetadataTable {
        public:
            uint32_t reserved;
            uint8_t major_version;
            uint8_t minor_version;
            uint8_t heap_sizes;
            uint8_t rid;
            uint64_t mask_valid;
            uint64_t mask_sorted;
            uint32_t table_entries[8 * 8] = { 0 };
            vector<TableEntry *> tables[8 * 8];
            uint32_t ParseTablePointers(char *&buffer);
            BINLEX_EXPORT uint32_t ParseTables(char *&buffer);
            BINLEX_EXPORT ~Cor20MetadataTable();
	};

    struct COR20_STREAM_HEADER {
		uint32_t offset;
		uint32_t size;
		char *name;
	};

	struct COR20_STORAGE_HEADER {
		uint8_t flags;
        uint8_t pad;
        uint16_t number_of_streams;
	};

	struct COR20_STORAGE_SIGNATURE {
		uint32_t signature;
		uint16_t major_version;
		uint16_t minor_version;
		uint32_t extra_data;
		uint32_t version_string_size;
		unsigned char *version_string;
	};

    struct COR20_HEADER {
        uint32_t cb;
        uint16_t major_runtime_version;
        uint16_t minor_runtime_version;
        uint32_t metadata_rva;
        uint32_t metadata_size;
        uint32_t flags;
        uint32_t entry_point_token_rva;
        uint32_t resources_rva;
        uint32_t resources_size;
        uint32_t strong_name_signature_rva;
        uint32_t strong_name_signature_size;
        uint32_t code_manager_table_rva;
        uint32_t code_manager_table_size;
        uint32_t vtable_fixups_rva;
        uint32_t vtable_fixups_size;
        uint32_t export_address_table_jumps_rva;
        uint32_t export_address_table_jumps_size;
        uint32_t managed_native_header_rva;
        uint32_t managed_native_header_size;
    };
};


namespace binlex {
    class DOTNET : public PE {
        private:
            void ParseSections();
            bool ParseCor20Header();
            bool ParseCor20StorageSignature();
            bool ParseCor20StorageHeader();
            bool ParseCor20StreamsHeader();
            bool ParseCor20MetadataStream();
        public:
			dotnet::COR20_HEADER cor20_header = { 0 };
			dotnet::COR20_STORAGE_SIGNATURE cor20_storage_signature = { 0 };
			dotnet::COR20_STORAGE_HEADER cor20_storage_header = { 0 };
            dotnet::COR20_STREAM_HEADER **StreamsHeader = { 0 };
            dotnet::Cor20MetadataTable cor20_metadata_table;

            vector<Section> _sections;
            BINLEX_EXPORT virtual bool ReadVector(const std::vector<uint8_t> &data);
            BINLEX_EXPORT bool Parse();
            BINLEX_EXPORT ~DOTNET();

    };
};
#endif
