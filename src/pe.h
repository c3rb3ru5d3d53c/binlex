#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include "common.h"

#ifndef PE_H
#define PE_H

#define PE_MAGIC_PE          0x4550
#define PE_MAGIC_MZ          0x4d5a
#define PE_MAX_DLL_NAME      256
#define PE_MAX_FUNCTION_NAME 512
#define PE_MODE_UNSET        0
#define PE_MODE_X86          1
#define PE_MODE_X86_64       2
#define PE_MAX_SECTIONS      32
#define PE_SECTION_NAME_SIZE 8
#define PE_MAX_DIRECTORIES   16

typedef enum {
	IMAGE_DIRECTORY_ENTRY_EXPORT			= 0, // Export Table
	IMAGE_DIRECTORY_ENTRY_IMPORT			= 1, // Import Table
	IMAGE_DIRECTORY_ENTRY_RESOURCE			= 2, // Resource Table
	IMAGE_DIRECTORY_ENTRY_EXCEPTION			= 3, // Exception Table
	IMAGE_DIRECTORY_ENTRY_SECURITY			= 4, // Certificate Table
	IMAGE_DIRECTORY_ENTRY_BASERELOC			= 5, // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG				= 6, // Debug
	//IMAGE_DIRECTORY_ENTRY_COPYRIGHT			= 7, // (X86 usage)
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE		= 7, // Architecture
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR			= 8, // Global Ptr
	IMAGE_DIRECTORY_ENTRY_TLS				= 9, // TLS Table
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG		= 10, // Load Config Table
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT		= 11, // Bound Import
	IMAGE_DIRECTORY_ENTRY_IAT				= 12, // IAT
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT		= 13, // Delay Import Descriptor
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	= 14, // CLR Runtime Header
	IMAGE_DIRECTORY_RESERVED				= 15  // Reserved, must be zero
} ImageDirectoryEntry;

typedef struct {
	uint32_t Characteristics;
	uint32_t TimeDateStamp;
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	uint32_t Name;
	uint32_t Base;
	uint32_t NumberOfFunctions;
	uint32_t NumberOfNames;
	uint32_t AddressOfFunctions;
	uint32_t AddressOfNames;
	uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct {
	uint32_t StartAddressOfRawData;
	uint32_t EndAddressOfRawData;
	uint32_t AddressOfIndex;
	uint32_t AddressOfCallBacks; // PIMAGE_TLS_CALLBACK
	uint32_t SizeOfZeroFill;
	uint32_t Characteristics; // reserved for future use
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

typedef struct {
	uint64_t StartAddressOfRawData;
	uint64_t EndAddressOfRawData;
	uint64_t AddressOfIndex;
	uint64_t AddressOfCallBacks;
	uint32_t SizeOfZeroFill;
	uint32_t Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

typedef struct {
	uint32_t VirtualAddress;
	uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef enum {
	IMAGE_FILE_MACHINE_UNKNOWN		= 0x0,
	IMAGE_FILE_MACHINE_AM33			= 0x1d3,
	IMAGE_FILE_MACHINE_AMD64		= 0x8664,
	IMAGE_FILE_MACHINE_ARM			= 0x1c0,
	IMAGE_FILE_MACHINE_ARMV7		= 0x1c4,
	IMAGE_FILE_MACHINE_CEE			= 0xc0ee,
	IMAGE_FILE_MACHINE_EBC			= 0xebc,
	IMAGE_FILE_MACHINE_I386			= 0x14c,
	IMAGE_FILE_MACHINE_IA64			= 0x200,
	IMAGE_FILE_MACHINE_M32R			= 0x9041,
	IMAGE_FILE_MACHINE_MIPS16		= 0x266,
	IMAGE_FILE_MACHINE_MIPSFPU		= 0x366,
	IMAGE_FILE_MACHINE_MIPSFPU16	= 0x466,
	IMAGE_FILE_MACHINE_POWERPC		= 0x1f0,
	IMAGE_FILE_MACHINE_POWERPCFP	= 0x1f1,
	IMAGE_FILE_MACHINE_R4000		= 0x166,
	IMAGE_FILE_MACHINE_SH3			= 0x1a2,
	IMAGE_FILE_MACHINE_SH3DSP		= 0x1a3,
	IMAGE_FILE_MACHINE_SH4			= 0x1a6,
	IMAGE_FILE_MACHINE_SH5			= 0x1a8,
	IMAGE_FILE_MACHINE_THUMB		= 0x1c2,
	IMAGE_FILE_MACHINE_WCEMIPSV2	= 0x169
} MachineType;

typedef enum {
	// Image only, Windows CE, Windows NT and above. Indicates that the
	// file does not contain base relocations and must therefore be
	// loaded at its preferred base address. If the base address is not
	// available, the loader reports an error. The default behavior of
	// the linker is to strip base relocations from EXEs.
	IMAGE_FILE_RELOCS_STRIPPED			= 0x0001,

	// Image only. Indicates that the image file is valid and can be run.
	// If this flag is not set, it indicates a linker error.
	IMAGE_FILE_EXECUTABLE_IMAGE			= 0x0002,

	// COFF line numbers have been removed.
	// Deprecated and should be zero.
	IMAGE_FILE_LINE_NUMS_STRIPPED		= 0x0004,

	// COFF symbol table entries for local symbols have been removed.
	// Deprecated and should be zero.
	IMAGE_FILE_LOCAL_SYMS_STRIPPED		= 0x0008,

	// Obsolete. Aggressively trim working set.
	// Deprecated in Windows 2000 and later. Must be zero.
	IMAGE_FILE_AGGRESSIVE_WS_TRIM		= 0x0010,

	// App can handle > 2gb addresses.
	IMAGE_FILE_LARGE_ADDRESS_AWARE		= 0x0020,

	// Reserved for future use.
	IMAGE_FILE_RESERVED					= 0x0040,

	// Little endian: LSB precedes MSB in memory.
	// Deprecated and should be zero.
	IMAGE_FILE_BYTES_REVERSED_LO		= 0x0080,

	// Machine based on 32-bit-word architecture.
	IMAGE_FILE_32BIT_MACHINE			= 0x0100,

	// Debugging information removed from image file.
	IMAGE_FILE_DEBUG_STRIPPED			= 0x0200,

	// If image is on removable media, fully load it and copy it to the
	// swap file.
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	= 0x0400,

	// If image is on network media, fully load it and copy it to the
	// swap file.
	IMAGE_FILE_NET_RUN_FROM_SWAP		= 0x0800,

	// The image file is a system file, not a user program.
	IMAGE_FILE_SYSTEM					= 0x1000,

	// The image file is a dynamic-link library (DLL). Such files are
	// considered executable files for almost all purposes, although
	// they cannot be directly run.
	IMAGE_FILE_DLL						= 0x2000,

	// File should be run only on a UP machine.
	IMAGE_FILE_UP_SYSTEM_ONLY			= 0x4000,

	// Big endian: MSB precedes LSB in memory.
	// Deprecated and should be zero.
	IMAGE_FILE_BYTES_REVERSED_HI		= 0x8000
} ImageCharacteristics;

typedef struct {
    uint32_t Signature;
	uint16_t Machine; // MachineType
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics; // ImageCharacteristics
} IMAGE_FILE_HEADER, IMAGE_COFF_HEADER, *PIMAGE_FILE_HEADER, *PIMAGE_COFF_HEADER;

typedef struct {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	uint32_t e_lfanew; // sizeof(IMAGE_DOS_HEADER) + size of MS-DOS stub
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// REFERENCE: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
typedef enum {
	// Unknown subsystem
	IMAGE_SUBSYSTEM_UNKNOWN						= 0,
	// No subsystem required (device drivers and native system processes)
	IMAGE_SUBSYSTEM_NATIVE						= 1,
	// Windows graphical user interface (GUI) subsystem
	IMAGE_SUBSYSTEM_WINDOWS_GUI					= 2,
	// Windows character-mode user interface (CUI) subsystem
	IMAGE_SUBSYSTEM_WINDOWS_CUI					= 3,
	// OS/2 CUI subsystem
	IMAGE_SUBSYSTEM_OS2_CUI						= 5,
	// POSIX CUI subsystem
	IMAGE_SUBSYSTEM_POSIX_CUI					= 7,
	// Windows CE system
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI				= 9,
	// Extensible Firmware Interface (EFI) application
	IMAGE_SUBSYSTEM_EFI_APPLICATION				= 10,
	// EFI driver with boot services
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 	= 11,
	// EFI driver with run-time services
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER			= 12,
	// EFI ROM image
	IMAGE_SUBSYSTEM_EFI_ROM						= 13,
	// Xbox system
	IMAGE_SUBSYSTEM_XBOX						= 14,
	// Boot application.
	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION	= 16
} WindowsSubsystem;

// REFERENCE: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
typedef enum {
	// IMAGE_DLLCHARACTERISTICS_RESERVED_1			= 0x0001,
	// IMAGE_DLLCHARACTERISTICS_RESERVED_2			= 0x0002,
	// IMAGE_DLLCHARACTERISTICS_RESERVED_4			= 0x0004,
	// IMAGE_DLLCHARACTERISTICS_RESERVED_8			= 0x0008,
	// The DLL can be relocated at load time.
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE			= 0x0040,
	// Code integrity checks are forced.
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY		= 0x0080,
	// The image is compatible with data execution prevention (DEP).
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT				= 0x0100,
	// The image is isolation aware, but should not be isolated.
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION			= 0x0200,
	// The image does not use structured exception handling (SEH).
	// No handlers can be called in this image.
	IMAGE_DLLCHARACTERISTICS_NO_SEH					= 0x0400,
	// Do not bind the image.
	IMAGE_DLLCHARACTERISTICS_NO_BIND				= 0x0800,
	// IMAGE_DLLCHARACTERISTICS_RESERVED_1000		= 0x1000,
	// A WDM driver.
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER				= 0x2000,
	// IMAGE_DLLCHARACTERISTICS_RESERVED_4000		= 0x4000,
	// The image is terminal server aware.
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE	= 0x8000
} ImageDllCharacteristics;

typedef enum {
	MAGIC_ROM	= 0x107,
	MAGIC_PE32	= 0x10b,
	MAGIC_PE64	= 0x20b // PE32+
} opt_type_e;

typedef struct {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	uint32_t BaseOfBss;
	uint32_t GprMask;
	uint32_t CprMask[4];
	uint32_t GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;

// REFERENCE: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
typedef struct {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData; // only in PE32
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Reserved1;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem; // WindowsSubsystem
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[PE_MAX_DIRECTORIES];
} IMAGE_OPTIONAL_HEADER_32, *PIMAGE_OPTIONAL_HEADER_32;

// REFERENCE: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
typedef struct {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Reserved1;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem; // WindowsSubsystem
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags; /* must be zero */
	uint32_t NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[PE_MAX_DIRECTORIES];
} IMAGE_OPTIONAL_HEADER_64, *PIMAGE_OPTIONAL_HEADER_64;

typedef struct {
	uint16_t type; // opt_type_e
	size_t length;
	IMAGE_OPTIONAL_HEADER_32 *_32;
	IMAGE_OPTIONAL_HEADER_64 *_64;
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef enum {
	IMAGE_SCN_TYPE_NO_PAD				= 0x00000008, // Obsolete. Replaced by IMAGE_SCN_ALIGN_1BYTES
	IMAGE_SCN_CNT_CODE					= 0x00000020,
	IMAGE_SCN_CNT_INITIALIZED_DATA		= 0x00000040,
	IMAGE_SCN_CNT_UNINITIALIZED_DATA	= 0x00000080,
	IMAGE_SCN_LNK_OTHER					= 0x00000100, // Reserved.
	IMAGE_SCN_LNK_INFO					= 0x00000200, // Valid only for object files.
	IMAGE_SCN_LNK_REMOVE				= 0x00000800, // Valid only for object files.
	IMAGE_SCN_LNK_COMDAT				= 0x00001000, // Valid only for object files.
	IMAGE_SCN_NO_DEFER_SPEC_EXC			= 0x00004000,
	IMAGE_SCN_GPREL						= 0x00008000,
	IMAGE_SCN_MEM_PURGEABLE				= 0x00020000, // Reserved.
	IMAGE_SCN_MEM_LOCKED				= 0x00040000, // Reserved.
	IMAGE_SCN_MEM_PRELOAD				= 0x00080000, // Reserved.
	IMAGE_SCN_ALIGN_1BYTES				= 0x00100000, // Valid only for object files.
	IMAGE_SCN_ALIGN_2BYTES				= 0x00200000, // Valid only for object files.
	IMAGE_SCN_ALIGN_4BYTES				= 0x00300000, // Valid only for object files.
	IMAGE_SCN_ALIGN_8BYTES				= 0x00400000, // Valid only for object files.
	IMAGE_SCN_ALIGN_16BYTES				= 0x00500000, // Valid only for object files.
	IMAGE_SCN_ALIGN_32BYTES				= 0x00600000, // Valid only for object files.
	IMAGE_SCN_ALIGN_64BYTES				= 0x00700000, // Valid only for object files.
	IMAGE_SCN_ALIGN_128BYTES			= 0x00800000, // Valid only for object files.
	IMAGE_SCN_ALIGN_256BYTES			= 0x00900000, // Valid only for object files.
	IMAGE_SCN_ALIGN_512BYTES			= 0x00A00000, // Valid only for object files.
	IMAGE_SCN_ALIGN_1024BYTES			= 0x00B00000, // Valid only for object files.
	IMAGE_SCN_ALIGN_2048BYTES			= 0x00C00000, // Valid only for object files.
	IMAGE_SCN_ALIGN_4096BYTES			= 0x00D00000, // Valid only for object files.
	IMAGE_SCN_ALIGN_8192BYTES			= 0x00E00000, // Valid only for object files.
	IMAGE_SCN_LNK_NRELOC_OVFL			= 0x01000000,
	IMAGE_SCN_MEM_DISCARDABLE			= 0x02000000,
	IMAGE_SCN_MEM_NOT_CACHED			= 0x04000000,
	IMAGE_SCN_MEM_NOT_PAGED				= 0x08000000,
	IMAGE_SCN_MEM_SHARED				= 0x10000000,
	IMAGE_SCN_MEM_EXECUTE				= 0x20000000,
	IMAGE_SCN_MEM_READ					= 0x40000000,
	IMAGE_SCN_MEM_WRITE					= -2147483648 // Same as 0x80000000
} SectionCharacteristics;

typedef struct {
	uint8_t Name[PE_SECTION_NAME_SIZE]; // TODO: Should we use char instead?
	union {
		uint32_t PhysicalAddress; // same value as next field
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations; // always zero in executables
	uint32_t PointerToLinenumbers; // deprecated
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers; // deprecated
	uint32_t Characteristics; // SectionCharacteristics
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// typedef struct {
// 	IMAGE_DOS_HEADER dos_hdr;
// 	uint32_t signature;
// 	IMAGE_COFF_HEADER coff_hdr;
// 	void *optional_hdr_ptr;
// 	IMAGE_OPTIONAL_HEADER optional_hdr;
// 	uint32_t num_directories;
// 	void *directories_ptr;
// 	IMAGE_DATA_DIRECTORY **directories;
// 	uint16_t num_sections;
// 	void *sections_ptr;
// 	IMAGE_SECTION_HEADER **sections;
// 	uint64_t entrypoint;
// 	uint64_t imagebase;
// } PE_HEADER, *PPE_HEADER;

class Pe {
    private:
        struct Section {
            int offset;
            int size;
            void *data;
        };
        bool is_pe(){
            if (dos_header->e_magic != 23117 ||
                coff_header->Signature != 17744){
                return false;
            }
            return true;
        }
    public:
        char magic_mz[2]               = {0x5a, 0x4d};
        char magic_pe[4]               = {0x00, 0x00, 0x45, 0x50};
        FILE *fd                       = NULL;
        PIMAGE_DOS_HEADER dos_header   = NULL;
        PIMAGE_COFF_HEADER coff_header = NULL;
        uint32_t pe_header_ptr         = 0;
        PIMAGE_OPTIONAL_HEADER_32 optional_header_32 = NULL;
        PIMAGE_OPTIONAL_HEADER_64 optional_header_64 = NULL;
        PIMAGE_SECTION_HEADER section_header = NULL;
        int mode                       = PE_MODE_UNSET;
        struct Section sections[PE_MAX_SECTIONS];
        Pe(){
            for (int i = 0; i < PE_MAX_SECTIONS; i++){
                sections[i].size = 0;
                sections[i].offset = 0;
                sections[i].data = NULL;
            }
        }
        bool Setup(int input_mode){
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
        bool ReadFile(char *file_path){
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
                    //printf("PointerToRawData: %x\n", section_header->PointerToRawData);
                    //printf("SizeofRawData   : %d\n", section_header->SizeOfRawData);
                    //common_hex_dump((char *)"section", sections[i].data, sections[i].size);
                    fseek(fd, set, SEEK_SET);
                }

            }
            return true;
        }
        ~Pe(){
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
};

#endif
