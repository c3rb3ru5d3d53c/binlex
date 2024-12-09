use std::mem;

/// Represents a metadata token type in a .NET metadata structure.
///
/// The `MetadataToken` enum defines various types of metadata tokens used to identify
/// rows in different metadata tables within a .NET assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataToken {
    Module = 0,
    TypeRef = 1,
    TypeDef = 2,
    FieldPtr = 3,
    Field = 4,
    MethodPtr = 5,
    MethodDef = 6,
    ParamPtr = 7,
    Param = 8,
    InterfaceImpl = 9,
    MemberRef = 10,
    Constant = 11,
    CustomAttribute = 12,
    FieldMarshal = 13,
    DeclSecurity = 14,
    ClassLayout = 15,
    FieldLayout = 16,
    StandAloneSig = 17,
    EventMap = 18,
    EventPtr = 19,
    Event = 20,
    PropertyMap = 21,
    PropertyPtr = 22,
    Property = 23,
    MethodSemantics = 24,
    MethodImpl = 25,
    ModuleRef = 26,
    TypeSpec = 27,
    ImplMap = 28,
    FieldRva = 29,
    EncLog = 30,
    EncMap = 31,
    Assembly = 32,
    AssemblyProcessor = 33,
    AssemblyOs = 34,
    AssemblyRef = 35,
    AssemblyRefProcessor = 36,
    AssemblyRefOs = 37,
    File = 38,
    ExportedType = 39,
    ManifestResource = 40,
    NestedClass = 41,
    GenericParam = 42,
    MethodSpec = 43,
    GenericParamConstraint = 44,
    Document = 48,
    MethodDebugInformation = 49,
    LocalScope = 50,
    LocalVariable = 51,
    LocalConstant = 52,
    ImportScope = 53,
    StateMachineMethod = 54,
    CustomDebugInformation = 55,
}

/// Represents an image data directory in a .NET metadata structure.
///
/// The `ImageDataDirectory` provides information about a specific data directory,
/// including its virtual address and size.
#[repr(C)]
pub struct ImageDataDirectory {
    /// A `u32` value representing the virtual address of the data directory.
    pub virtual_address: u32,
    /// A `u32` value representing the size of the data directory.
    pub size: u32,
}

/// Represents the anonymous field in the `Cor20Header`, used to define the entry point.
///
/// The `Cor20Header0` union allows for two possible representations:
/// an entry point token for managed code or an RVA for native code.
#[repr(C)]
pub union Cor20Header0 {
    /// A `u32` value representing the entry point token for managed code.
    pub entry_point_token: u32,
    /// A `u32` value representing the RVA of the entry point for native code.
    pub entry_point_rva: u32,
}

/// Represents the .NET COR20 header in a PE file.
///
/// The `Cor20Header` provides information about the Common Language Runtime (CLR)
/// metadata, versioning, and related data structures required for .NET assemblies.
#[repr(C)]
pub struct Cor20Header {
    /// A `u32` value representing the size of the header in bytes.
    pub cb: u32,
    /// A `u16` value indicating the major version of the CLR runtime.
    pub major_runtime_version: u16,
    /// A `u16` value indicating the minor version of the CLR runtime.
    pub minor_runtime_version: u16,
    /// An `ImageDataDirectory` pointing to the metadata.
    pub meta_data: ImageDataDirectory,
    /// A `u32` value representing various flags related to the assembly.
    pub flags: u32,
    /// A `Cor20Header0` union containing either an entry point token or an RVA.
    pub anonymous: Cor20Header0,
    /// An `ImageDataDirectory` pointing to resources in the assembly.
    pub resources: ImageDataDirectory,
    /// An `ImageDataDirectory` pointing to the strong name signature.
    pub strong_name_signature: ImageDataDirectory,
    /// An `ImageDataDirectory` pointing to the code manager table.
    pub code_manager_table: ImageDataDirectory,
    /// An `ImageDataDirectory` pointing to VTable fixups.
    pub vtable_fixups: ImageDataDirectory,
    /// An `ImageDataDirectory` pointing to export address table jumps.
    pub export_address_table_jumps: ImageDataDirectory,
    /// An `ImageDataDirectory` pointing to the managed native header.
    pub managed_native_header: ImageDataDirectory,
}

impl Cor20Header {
    /// Parses a `Cor20Header` from a byte slice.
    ///
    /// This function validates the size and alignment of the byte slice before returning
    /// a reference to the `Cor20Header`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `Cor20Header` data.
    ///
    /// # Returns
    ///
    /// * `Some(&Cor20Header)` - A reference to the parsed `Cor20Header` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid, does not contain enough data, or is misaligned.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() != mem::size_of::<Self>() {
            return None;
        }
        if bytes.as_ptr().align_offset(mem::align_of::<Self>()) != 0 {
            return None;
        }
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    pub fn size() -> usize {
        mem::size_of::<Self>()
    }
}

/// Represents the storage signature in a .NET metadata structure.
///
/// The `StorageSignature` contains metadata about the storage, including its signature,
/// version, and additional data fields.
#[repr(C)]
pub struct StorageSignature {
    /// A `u32` value representing the storage signature.
    pub signature: u32,
    /// A `u16` value indicating the major version of the storage.
    pub major_version: u16,
    /// A `u16` value indicating the minor version of the storage.
    pub minor_version: u16,
    /// A `u32` value containing additional data.
    pub extra_data: u32,
    /// A `u32` value specifying the size of the version string.
    pub version_string_size: u32,
    /// A `u32` value referencing the version string.
    pub version_string: u32,
}

impl StorageSignature {
    /// Parses a `StorageSignature` from a byte slice.
    ///
    /// This function validates the size and alignment of the byte slice before returning
    /// a reference to the `StorageSignature`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `StorageSignature` data.
    ///
    /// # Returns
    ///
    /// * `Some(&StorageSignature)` - A reference to the parsed `StorageSignature` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid, does not contain enough data, or is misaligned.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() != mem::size_of::<Self>() {
            return None;
        }
        if bytes.as_ptr().align_offset(mem::align_of::<Self>()) != 0 {
            return None;
        }
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    pub fn size() -> usize {
        mem::size_of::<Self>()
    }
}

/// Represents the storage header in a .NET metadata structure.
///
/// The `StorageHeader` provides metadata about the storage streams, including the number
/// of streams and associated flags.
#[repr(C)]
pub struct StorageHeader {
    /// A `u8` value representing the storage flags.
    pub flags: u8,
    /// A `u8` value for padding (reserved).
    pub pad: u8,
    /// A `u16` value indicating the number of streams in the storage.
    pub number_of_streams: u16,
}

impl StorageHeader {
    /// Parses a `StorageHeader` from a byte slice.
    ///
    /// This function validates the size and alignment of the byte slice before returning
    /// a reference to the `StorageHeader`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `StorageHeader` data.
    ///
    /// # Returns
    ///
    /// * `Some(&StorageHeader)` - A reference to the parsed `StorageHeader` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid, does not contain enough data, or is misaligned.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() != mem::size_of::<Self>() {
            return None;
        }
        if bytes.as_ptr().align_offset(mem::align_of::<Self>()) != 0 {
            return None;
        }
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    pub fn size() -> usize {
        mem::size_of::<Self>()
    }
}

/// Represents a stream header in a .NET metadata structure.
///
/// The `StreamHeader` contains metadata about a stream, including its offset and size,
/// and provides methods to retrieve its name and the total header size.
#[repr(C)]
pub struct StreamHeader {
    /// The offset of the stream in the metadata section.
    pub offset: u32,
    /// The size of the stream in bytes.
    pub size: u32,
}

impl StreamHeader {
    /// Parses a `StreamHeader` from a byte slice.
    ///
    /// This function validates that the byte slice contains enough data for a `StreamHeader`
    /// and returns a reference to it.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `StreamHeader` data.
    ///
    /// # Returns
    ///
    /// * `Some(&StreamHeader)` - A reference to the parsed `StreamHeader` if the byte slice is valid.
    /// * `None` - If the byte slice is too short to contain a valid `StreamHeader`.
    ///
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() < mem::size_of::<StreamHeader>() {
            return None;
        }
        Some(unsafe { &*(bytes.as_ptr() as *const StreamHeader) })
    }

    /// Retrieves the name of the stream as a byte slice, including any padding.
    ///
    /// This method locates the null-terminated name string following the `StreamHeader` fields
    /// and includes padding up to a 4-byte boundary.
    ///
    /// # Returns
    ///
    /// * `&[u8]` - A slice containing the name of the stream with padding.
    pub fn name(&self) -> &[u8] {
        let header_size = mem::size_of::<StreamHeader>();
        let base_ptr = self as *const Self as *const u8;

        unsafe {
            let name_ptr = base_ptr.add(header_size);

            let mut len = 0;
            while *name_ptr.add(len) != 0 {
                len += 1;
            }

            let padded_len = (len + 4) & !3;

            std::slice::from_raw_parts(name_ptr, padded_len)
        }
    }

    /// Calculates the total size of the `StreamHeader` including the name and padding.
    ///
    /// The size includes the fixed fields of the `StreamHeader` and the length of the name
    /// (rounded to a 4-byte boundary).
    ///
    /// # Returns
    ///
    /// * `usize` - The total size of the `StreamHeader` in bytes.
    pub fn size() -> usize {
        mem::size_of::<Self>()
        // let header_size = mem::size_of::<StreamHeader>();
        // header_size + self.name().len()
    }
}

/// Represents a Metadata Table header in a .NET metadata structure.
///
/// The `MetadataTable` provides information about the structure and versioning of 
/// the metadata, as well as the sizes and characteristics of various heaps.
#[repr(C)]
pub struct MetadataTable {
    /// Reserved space, typically set to zero.
    pub reserved: u32,
    /// The major version of the metadata.
    pub major_version: u8,
    /// The minor version of the metadata.
    pub minor_version: u8,
    /// A bitfield indicating the sizes of the various heaps (e.g., String, GUID, Blob).
    pub heap_sizes: u8,
    /// The RID (Row ID) base, typically used for addressing rows in tables.
    pub rid: u8,
    /// A bitmask indicating which tables are present in the metadata.
    pub mask_valid: u64,
    /// A bitmask indicating which tables are sorted.
    pub mask_sorted: u64,
}

impl MetadataTable {
    /// Parses a `MetadataTable` from a byte slice.
    ///
    /// This function validates the size and alignment of the byte slice before 
    /// returning a reference to the `MetadataTable`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `MetadataTable` data.
    ///
    /// # Returns
    ///
    /// * `Some(&MetadataTable)` - A reference to the parsed `MetadataTable` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid, does not contain enough data, or is misaligned.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() != mem::size_of::<Self>() {
            return None;
        }
        if bytes.as_ptr().align_offset(mem::align_of::<Self>()) != 0 {
            return None;
        }
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    pub fn size() -> usize {
        mem::size_of::<Self>()
    }
}

/// Represents an entry in the Module table in a .NET metadata structure.
///
/// The `ModuleEntry` provides information about a module, including its generation,
/// name, and GUIDs for module versioning and edit-and-continue (ENC) information.
#[repr(C)]
pub struct ModuleEntry {
    /// A `u16` value representing the generation of the module.
    pub generation: u16,
    /// A `StringHeapIndex` referencing the module's name in the String heap.
    pub name: StringHeapIndex,
    /// A `GuidHeapIndex` referencing the module version ID in the GUID heap.
    pub mv_id: GuidHeapIndex,
    /// A `GuidHeapIndex` referencing the edit-and-continue (ENC) ID in the GUID heap.
    pub enc_id: GuidHeapIndex,
    /// A `GuidHeapIndex` referencing the edit-and-continue base ID in the GUID heap.
    pub enc_base_id: GuidHeapIndex,
}

impl ModuleEntry {
    /// Parses a `ModuleEntry` from a byte slice based on the heap size.
    ///
    /// This function extracts the fields of the `ModuleEntry` from the given byte slice,
    /// validating and parsing each component, such as `StringHeapIndex` and `GuidHeapIndex`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `ModuleEntry` data.
    /// * `heap_size` - A `u8` value indicating the size of the heap, which affects how indices are parsed.
    ///
    /// # Returns
    ///
    /// * `Some(ModuleEntry)` - The parsed `ModuleEntry` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        if bytes.len() < 2 { return None; }
        let generation = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let mut offset: usize = mem::size_of::<u16>();
        let name = StringHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += name.size();
        let mv_id = GuidHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += mv_id.size();
        let enc_id = GuidHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += enc_id.size();
        let enc_base_id = GuidHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        Some(Self {
            generation,
            name,
            mv_id,
            enc_id,
            enc_base_id,
        })
    }

    /// Returns the size of the `ModuleEntry` in bytes.
    ///
    /// This method calculates the size of the entry, accounting for variable-sized
    /// fields like `StringHeapIndex` and `GuidHeapIndex`.
    ///
    /// # Returns
    ///
    /// * `usize` - The total size of the `ModuleEntry` in bytes.
    pub fn size(&self) -> usize {
        let mut size: usize = mem::size_of::<u16>();
        size += self.name.size();
        size += self.mv_id.size();
        size += self.enc_id.size();
        size += self.enc_base_id.size();
        size
    }
}

/// Represents an entry in the TypeRef table in a .NET metadata structure.
///
/// The `TypeRefEntry` provides information about a type reference, including its
/// resolution scope, name, and namespace.
#[repr(C)]
pub struct TypeRefEntry {
    /// A `ResolutionScopeIndex` referencing the scope where the type is defined.
    pub resolution_scope: ResolutionScopeIndex,
    /// A `StringHeapIndex` referencing the type's name in the String heap.
    pub name: StringHeapIndex,
    /// A `StringHeapIndex` referencing the type's namespace in the String heap.
    pub namespace: StringHeapIndex,
}

impl TypeRefEntry {
    /// Parses a `TypeRefEntry` from a byte slice based on the heap size.
    ///
    /// This function extracts the fields of the `TypeRefEntry` from the given byte slice,
    /// validating and parsing each component, such as `ResolutionScopeIndex` and `StringHeapIndex`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `TypeRefEntry` data.
    /// * `heap_size` - A `u8` value indicating the size of the heap, which affects how indices are parsed.
    ///
    /// # Returns
    ///
    /// * `Some(TypeRefEntry)` - The parsed `TypeRefEntry` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        let mut offset: usize = 0;
        let resolution_scope = ResolutionScopeIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += resolution_scope.size();
        let name = StringHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += name.size();
        let namespace = StringHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        Some(Self {
            resolution_scope,
            name,
            namespace,
        })
    }

    /// Returns the size of the `TypeRefEntry` in bytes.
    ///
    /// This method calculates the size of the entry, accounting for variable-sized
    /// fields like `ResolutionScopeIndex` and `StringHeapIndex`.
    ///
    /// # Returns
    ///
    /// * `usize` - The total size of the `TypeRefEntry` in bytes.
    pub fn size(&self) -> usize {
        let mut size = self.resolution_scope.size();
        size += self.name.size();
        size += self.namespace.size();
        size
    }
}

/// Represents an entry in the TypeDef table in a .NET metadata structure.
///
/// The `TypeDefEntry` provides detailed information about a type definition,
/// including its attributes, name, namespace, parent type, and lists of fields and methods.
#[repr(C)]
pub struct TypeDefEntry {
    /// Type attributes specifying visibility, layout, and other characteristics.
    pub flags: u32,
    /// A `StringHeapIndex` referencing the type's name in the String heap.
    pub name: StringHeapIndex,
    /// A `StringHeapIndex` referencing the type's namespace in the String heap.
    pub namespace: StringHeapIndex,
    /// A `TypeDefOrRefIndex` referencing the base type or interface.
    pub extends: TypeDefOrRefIndex,
    /// A `SimpleTableIndex` pointing to the start of the field list for this type.
    pub field_list: SimpleTableIndex,
    /// A `SimpleTableIndex` pointing to the start of the method list for this type.
    pub method_list: SimpleTableIndex,
}

impl TypeDefEntry {
    /// Parses a `TypeDefEntry` from a byte slice based on the heap size.
    ///
    /// This function extracts the fields of the `TypeDefEntry` from the given byte slice,
    /// validating and parsing each component, such as `StringHeapIndex`, `TypeDefOrRefIndex`,
    /// and `SimpleTableIndex`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `TypeDefEntry` data.
    /// * `heap_size` - A `u8` value indicating the size of the heap, which affects how indices are parsed.
    ///
    /// # Returns
    ///
    /// * `Some(TypeDefEntry)` - The parsed `TypeDefEntry` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        if bytes.len() < 4 { return None; }
        let flags = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let mut offset: usize = mem::size_of::<u32>();
        let name = StringHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += name.size();
        let namespace = StringHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += namespace.size();
        let extends = TypeDefOrRefIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += extends.size();
        let field_list = SimpleTableIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += field_list.size();
        let method_list = SimpleTableIndex::from_bytes(&bytes[offset..], heap_size)?;
        Some(Self {
            flags,
            name,
            namespace,
            extends,
            field_list,
            method_list,
        })
    }

    /// Returns the size of the `TypeDefEntry` in bytes.
    ///
    /// This method calculates the size of the entry, accounting for variable-sized
    /// fields like `StringHeapIndex`, `TypeDefOrRefIndex`, and `SimpleTableIndex`.
    ///
    /// # Returns
    ///
    /// * `usize` - The total size of the `TypeDefEntry` in bytes.
    pub fn size(&self) -> usize {
        let mut size: usize = mem::size_of::<u32>();
        size += self.name.size();
        size += self.namespace.size();
        size += self.extends.size();
        size += self.field_list.size();
        size += self.method_list.size();
        size
    }
}

/// Represents an entry in the Field table in a .NET metadata structure.
///
/// The `FieldEntry` provides information about a field definition, including its
/// flags, name, and signature.
#[repr(C)]
pub struct FieldEntry {
    /// Field attributes specifying visibility, special behavior, and other characteristics.
    pub flags: u16,
    /// A `StringHeapIndex` referencing the field's name in the String heap.
    pub name: StringHeapIndex,
    /// A `BlobHeapIndex` referencing the field's signature in the Blob heap.
    pub signature: BlobHeapIndex,
}

impl FieldEntry {
    /// Parses a `FieldEntry` from a byte slice based on the heap size.
    ///
    /// This function extracts the fields of the `FieldEntry` from the given byte slice,
    /// validating and parsing each component, such as `StringHeapIndex` and `BlobHeapIndex`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `FieldEntry` data.
    /// * `heap_size` - A `u8` value indicating the size of the heap, which affects how indices are parsed.
    ///
    /// # Returns
    ///
    /// * `Some(FieldEntry)` - The parsed `FieldEntry` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        if bytes.len() < 2 { return None; }
        let flags = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let mut offset: usize = mem::size_of::<u16>();
        let name: StringHeapIndex = StringHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += name.size();
        let signature = BlobHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        Some(Self {
            flags,
            name,
            signature,
        })
    }

    /// Returns the size of the `FieldEntry` in bytes.
    ///
    /// This method calculates the size of the entry, accounting for variable-sized
    /// fields like `StringHeapIndex` and `BlobHeapIndex`.
    ///
    /// # Returns
    ///
    /// * `usize` - The total size of the `FieldEntry` in bytes.
    pub fn size(&self) -> usize {
        let mut size: usize = mem::size_of::<u16>();
        size += self.name.size();
        size += self.signature.size();
        size
    }
}

/// Represents an entry in the MethodDef table in a .NET metadata structure.
///
/// The `MethodDefEntry` provides detailed information about a method definition,
/// including its address, flags, name, signature, and parameters.
#[repr(C)]
pub struct MethodDefEntry {
    /// The relative virtual address (RVA) of the method's executable code.
    pub rva: u32,
    /// Implementation flags specifying method attributes.
    pub impl_flags: u16,
    /// Method flags specifying additional attributes.
    pub flags: u16,
    /// A `StringHeapIndex` referencing the method's name in the String heap.
    pub name: StringHeapIndex,
    /// A `BlobHeapIndex` referencing the method's signature in the Blob heap.
    pub signature: BlobHeapIndex,
    /// A `SimpleTableIndex` referencing the method's parameter list in the Parameter table.
    pub param_list: SimpleTableIndex,
}

impl MethodDefEntry {
    /// Parses a `MethodDefEntry` from a byte slice based on the heap size.
    ///
    /// This function extracts the fields of the `MethodDefEntry` from the given byte slice,
    /// validating and parsing each component, such as `StringHeapIndex`, `BlobHeapIndex`,
    /// and `SimpleTableIndex`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the `MethodDefEntry` data.
    /// * `heap_size` - A `u8` value indicating the size of the heap, which affects how indices are parsed.
    ///
    /// # Returns
    ///
    /// * `Some(MethodDefEntry)` - The parsed `MethodDefEntry` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        let rva = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let impl_flags = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let flags = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        let mut offset: usize = 8;
        let name = StringHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += name.size();
        let signature = BlobHeapIndex::from_bytes(&bytes[offset..], heap_size)?;
        offset += signature.size();
        let param_list = SimpleTableIndex::from_bytes(&bytes[offset..], heap_size)?;
        Some(Self{
            rva,
            impl_flags,
            flags,
            name,
            signature,
            param_list,
        })
    }

    /// Returns the size of the `MethodDefEntry` in bytes.
    ///
    /// This method calculates the size of the entry, accounting for variable-sized
    /// fields like `StringHeapIndex`, `BlobHeapIndex`, and `SimpleTableIndex`.
    ///
    /// # Returns
    ///
    /// * `usize` - The total size of the `MethodDefEntry` in bytes.
    pub fn size(&self) -> usize {
        let mut size: usize = 8;
        size += self.name.size();
        size += self.signature.size();
        size += self.param_list.size();
        size
    }
}

/// Represents an index into a simple table in a .NET metadata structure.
///
/// The `SimpleTableIndex` is used to reference entries in a metadata table,
/// such as the Method, Field, or TypeDef tables, depending on the context.
#[repr(C)]
pub struct SimpleTableIndex {
    /// The offset in the table where the entry starts.
    pub offset: u32,
    /// The size of the referenced entry in bytes.
    pub size: u32,
}

impl SimpleTableIndex {
    /// Parses a `SimpleTableIndex` from a byte slice based on the heap size.
    ///
    /// The size of the index (2 or 4 bytes) is determined by the `heap_size` parameter.
    /// The function validates the byte slice length before parsing.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the index data.
    /// * `heap_size` - A `u8` value indicating the size of the heap (used to determine 
    ///   whether the index is 2 or 4 bytes).
    ///
    /// # Returns
    ///
    /// * `Some(SimpleTableIndex)` - The parsed `SimpleTableIndex` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        let size = if heap_size & 1 != 0 { 4 } else { 2 };

        let offset = match size {
            2 if bytes.len() >= 2 => u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as u32,
            4 if bytes.len() >= 4 => u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            _ => return None,
        };

        Some(Self {
            offset,
            size,
        })
    }

    /// Returns the size of the referenced entry in the table.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the referenced entry in bytes.
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

/// Represents an index into the String heap in a .NET metadata structure.
///
/// The `StringHeapIndex` is used to reference entries in the String heap, which stores
/// strings used in metadata tables.
#[derive(Debug)]
pub struct StringHeapIndex {
    /// The offset in the String heap where the data starts.
    pub offset: u32,
    /// The size of the referenced data in bytes.
    pub size: u32,
}

impl StringHeapIndex {
    /// Parses a `StringHeapIndex` from a byte slice based on the heap size.
    ///
    /// The size of the index (2 or 4 bytes) is determined by the `heap_size` parameter.
    /// The function validates the byte slice length before parsing.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the index data.
    /// * `heap_size` - A `u8` value indicating the size of the heap (used to determine 
    ///   whether the index is 2 or 4 bytes).
    ///
    /// # Returns
    ///
    /// * `Some(StringHeapIndex)` - The parsed `StringHeapIndex` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        let size = if heap_size & 1 != 0 { 4 } else { 2 };

        let offset = match size {
            2 if bytes.len() >= 2 => u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as u32,
            4 if bytes.len() >= 4 => u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            _ => return None,
        };

        Some(Self {
            offset,
            size,
        })
    }

    /// Returns the size of the referenced data in the String heap.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the referenced data in bytes.
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

/// Represents an index into the GUID heap in a .NET metadata structure.
///
/// The `GuidHeapIndex` is used to reference entries in the GUID heap, which stores
/// globally unique identifiers (GUIDs) used in metadata tables.
#[derive(Debug)]
pub struct GuidHeapIndex {
    /// The offset in the GUID heap where the data starts.
    pub offset: u32,
    /// The size of the referenced data in bytes.
    pub size: u32,
}

impl GuidHeapIndex {
    /// Parses a `GuidHeapIndex` from a byte slice based on the heap size.
    ///
    /// The size of the index (2 or 4 bytes) is determined by the `heap_size` parameter.
    /// The function validates the byte slice length before parsing.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the index data.
    /// * `heap_size` - A `u8` value indicating the size of the heap (used to determine 
    ///   whether the index is 2 or 4 bytes).
    ///
    /// # Returns
    ///
    /// * `Some(GuidHeapIndex)` - The parsed `GuidHeapIndex` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        let size = if heap_size & 2 != 0 { 4 } else { 2 };

        let offset = match size {
            2 if bytes.len() >= 2 => u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as u32,
            4 if bytes.len() >= 4 => u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            _ => return None,
        };

        Some(Self {
            offset,
            size,
        })
    }

    /// Returns the size of the referenced data in the GUID heap.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the referenced data in bytes.
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

/// Represents an index into the ResolutionScope table in a .NET metadata structure.
///
/// The `ResolutionScopeIndex` is used to reference entries in the ResolutionScope table,
/// which includes assemblies, modules, and other scopes that define or reference types.
#[repr(C)]
pub struct ResolutionScopeIndex {
    /// The offset in the ResolutionScope table where the data starts.
    pub offset: u32,
    /// The offset in the ResolutionScope table where the data starts.
    pub size: u32,
}

impl ResolutionScopeIndex {
    /// Parses a `ResolutionScopeIndex` from a byte slice based on the heap size.
    ///
    /// The size of the index (2 or 4 bytes) is determined by the `heap_size` parameter.
    /// The function validates the byte slice length before parsing.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the index data.
    /// * `heap_size` - A `u8` value indicating the size of the heap (used to determine 
    ///   whether the index is 2 or 4 bytes).
    ///
    /// # Returns
    ///
    /// * `Some(ResolutionScopeIndex)` - The parsed `ResolutionScopeIndex` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        let size = if heap_size & 2 != 0 { 4 } else { 2 };

        let offset = match size {
            2 if bytes.len() >= 2 => u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as u32,
            4 if bytes.len() >= 4 => u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            _ => return None,
        };

        Some(Self {
            offset,
            size,
        })
    }

    /// Returns the size of the referenced data in the ResolutionScope table.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the referenced data in bytes.
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

/// Represents an index into the TypeDef or TypeRef table in a .NET metadata structure.
///
/// The `TypeDefOrRefIndex` is used to reference types defined or referenced in the
/// metadata tables, facilitating access to type definitions or references.
#[repr(C)]
#[derive(Debug)]
pub struct TypeDefOrRefIndex {
    /// The offset in the TypeDef or TypeRef table where the data starts.
    pub offset: u32,
    /// The size of the referenced data in bytes.
    pub size: u32,
}

impl TypeDefOrRefIndex {
    /// Parses a `TypeDefOrRefIndex` from a byte slice based on the heap size.
    ///
    /// The size of the index (2 or 4 bytes) is determined by the `heap_size` parameter.
    /// The function validates the byte slice length before parsing.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the index data.
    /// * `heap_size` - A `u8` value indicating the size of the heap (used to determine 
    ///   whether the index is 2 or 4 bytes).
    ///
    /// # Returns
    ///
    /// * `Some(TypeDefOrRefIndex)` - The parsed `TypeDefOrRefIndex` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        let size = if heap_size & 2 != 0 { 4 } else { 2 };

        let offset = match size {
            2 if bytes.len() >= 2 => u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as u32,
            4 if bytes.len() >= 4 => u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            _ => return None,
        };

        Some(Self {
            offset,
            size,
        })
    }

    /// Returns the size of the referenced data in the TypeDef or TypeRef table.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the referenced data in bytes.
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

/// Represents an index into the Blob heap in a .NET metadata structure.
///
/// The `BlobHeapIndex` is used to reference data in the Blob heap, which contains 
/// metadata such as constants, custom attributes, and signatures.
///
/// # Fields
///
/// * `offset` - The offset in the Blob heap where the data starts.
/// * `size` - The size of the referenced data in bytes.
#[repr(C)]
pub struct BlobHeapIndex {
    /// The offset in the Blob heap where the data starts.
    pub offset: u32,
    /// The size of the referenced data in bytes.
    pub size: u32,
}

impl BlobHeapIndex {
    /// Parses a `BlobHeapIndex` from a byte slice based on the heap size.
    ///
    /// The size of the index (2 or 4 bytes) is determined by the `heap_size` parameter.
    /// The function validates the byte slice length before parsing.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the index data.
    /// * `heap_size` - A `u8` value indicating the size of the heap (used to determine 
    ///   whether the index is 2 or 4 bytes).
    ///
    /// # Returns
    ///
    /// * `Some(BlobHeapIndex)` - The parsed `BlobHeapIndex` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or does not contain enough data.
    pub fn from_bytes(bytes: &[u8], heap_size: u8) -> Option<Self> {
        let size = if heap_size & 2 != 0 { 4 } else { 2 };

        let offset = match size {
            2 if bytes.len() >= 2 => u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as u32,
            4 if bytes.len() >= 4 => u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            _ => return None,
        };

        Some(Self {
            offset,
            size,
        })
    }

    /// Returns the size of the referenced data in the Blob heap.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the referenced data in bytes.
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

/// Represents an entry in the .NET metadata table.
///
/// Each entry corresponds to a specific metadata table type, such as `Module`, 
/// `TypeRef`, `TypeDef`, `Field`, or `MethodDef`.
///
/// # Variants
///
/// * `Module(ModuleEntry)` - Represents a module definition entry.
/// * `TypeRef(TypeRefEntry)` - Represents a type reference entry.
/// * `TypeDef(TypeDefEntry)` - Represents a type definition entry.
/// * `Field(FieldEntry)` - Represents a field entry.
/// * `MethodDef(MethodDefEntry)` - Represents a method definition entry.
pub enum Entry {
    Module(ModuleEntry),
    TypeRef(TypeRefEntry),
    TypeDef(TypeDefEntry),
    Field(FieldEntry),
    MethodDef(MethodDefEntry),
}

/// Represents a Tiny method header in a .NET executable.
///
/// The `TinyHeader` is a compact representation of method headers for small methods
/// with limited fields and constraints.
///
/// # Fields
///
/// * `code_size` - The size of the method's executable code in bytes.
#[repr(C)]
pub struct TinyHeader {
    /// The size of the method's executable code in bytes.
    pub code_size: u8,
}

impl TinyHeader {
    /// Parses a `TinyHeader` from a byte slice.
    ///
    /// This function validates the size and alignment of the byte slice before 
    /// returning a reference to the `TinyHeader`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the header data.
    ///
    /// # Returns
    ///
    /// * `Some(&TinyHeader)` - A reference to the parsed `TinyHeader` if the byte slice is valid.
    /// * `None` - If the byte slice is invalid or misaligned.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() != mem::size_of::<Self>() {
            return None;
        }
        if bytes.as_ptr().align_offset(mem::align_of::<Self>()) != 0 {
            return None;
        }
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    pub fn size(&self) -> usize {
        1
    }
}

/// Represents the method header in a .NET executable.
///
/// The method header can either be a `Tiny` or `Fat` header, depending on the 
/// method's structure and size.
///
/// # Variants
///
/// * `Tiny(TinyHeader)` - A compact method header with limited fields.
/// * `Fat(FatHeader)` - A full-featured method header with additional details.
pub enum MethodHeader {
    Tiny(TinyHeader),
    Fat(FatHeader),
}

impl MethodHeader {
    /// Returns the size of the method header in bytes.
    ///
    /// # Returns
    ///
    /// * `Some(usize)` - The size of the method header in bytes.
    /// * `None` - If the method header type is not recognized.
    pub fn size(&self) -> Option<usize> {
        match self {
            Self::Tiny(header) => Some(header.size()),
            Self::Fat(header) => Some(header.size()),
        }
    }

    /// Returns the size of the method's executable code in bytes.
    ///
    /// # Returns
    ///
    /// * `Some(usize)` - The size of the method's code.
    /// * `None` - If the method header type is not recognized.
    pub fn code_size(&self) -> Option<usize> {
        match self {
            Self::Tiny(header) => Some(header.code_size as usize),
            Self::Fat(header) => Some(header.code_size as usize),
        }
    }
}

/// Represents a fat method header in a .NET executable.
///
/// The fat header provides detailed information about a method, including its 
/// flags, stack size, code size, and local variable signature token.
#[repr(C)]
pub struct FatHeader {
    /// Flags indicating the method's attributes.
    pub flags: u16,
    /// The maximum stack depth required by the method.
    pub max_stack: u16,
    /// The size of the method's executable code in bytes.
    pub code_size: u32,
    /// A metadata token for the method's local variable signature.
    pub local_var_sig_token: u32,
}

impl FatHeader {
    /// Parses a `FatHeader` from a byte slice.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A byte slice containing the header data.
    ///
    /// # Returns
    ///
    /// * `Ok(FatHeader)` - The parsed `FatHeader`.
    /// * `Err(std::io::Error)` - If the byte slice is too short or invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice does not contain enough data to parse a valid `FatHeader`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        if bytes.len() < 12 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Not enough bytes for FatHeader"));
        }

        Ok(Self {
            flags: u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
            max_stack: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            code_size: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            local_var_sig_token: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        })
    }

    /// Returns the size of the `FatHeader` in bytes.
    ///
    /// # Returns
    ///
    /// * `usize` - The size of the `FatHeader`, which is always 12 bytes.
    pub fn size(&self) -> usize {
        12
    }
}
