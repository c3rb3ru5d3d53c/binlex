#![allow(dead_code, non_camel_case_types)]

use std::ffi::c_void;
use std::os::raw::c_char;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirAsmState {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirContext {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirDialect {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirDialectRegistry {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirDialectHandle {
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirOperation {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirOpPrintingFlags {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirBytecodeWriterConfig {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirOpOperand {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirBlock {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirRegion {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirSymbolTable {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirAttribute {
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirIdentifier {
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirLocation {
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirModule {
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirType {
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirTypeID {
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirValue {
    pub ptr: *const c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirPass {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirPassManager {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirOpPassManager {
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirStringRef {
    pub data: *const c_char,
    pub length: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirLogicalResult {
    pub value: i8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirNamedAttribute {
    pub name: MlirIdentifier,
    pub attribute: MlirAttribute,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MlirOperationState {
    pub name: MlirStringRef,
    pub location: MlirLocation,
    pub n_results: isize,
    pub results: *mut MlirType,
    pub n_operands: isize,
    pub operands: *mut MlirValue,
    pub n_regions: isize,
    pub regions: *mut MlirRegion,
    pub n_successors: isize,
    pub successors: *mut MlirBlock,
    pub n_attributes: isize,
    pub attributes: *mut MlirNamedAttribute,
    pub enable_result_type_inference: bool,
}

pub type MlirStringCallback = Option<unsafe extern "C" fn(MlirStringRef, *mut c_void)>;

unsafe extern "C" {
    pub fn mlirRegisterAllDialects(registry: MlirDialectRegistry);

    pub fn mlirDialectRegistryCreate() -> MlirDialectRegistry;
    pub fn mlirDialectRegistryDestroy(registry: MlirDialectRegistry);

    pub fn mlirDialectHandleGetNamespace(handle: MlirDialectHandle) -> MlirStringRef;
    pub fn mlirDialectHandleInsertDialect(handle: MlirDialectHandle, registry: MlirDialectRegistry);
    pub fn mlirDialectHandleRegisterDialect(handle: MlirDialectHandle, context: MlirContext);
    pub fn mlirDialectHandleLoadDialect(
        handle: MlirDialectHandle,
        context: MlirContext,
    ) -> MlirDialect;

    pub fn mlirGetDialectHandle__func__() -> MlirDialectHandle;
    pub fn mlirGetDialectHandle__cf__() -> MlirDialectHandle;
    pub fn mlirGetDialectHandle__arith__() -> MlirDialectHandle;
    pub fn mlirGetDialectHandle__scf__() -> MlirDialectHandle;
    pub fn mlirGetDialectHandle__memref__() -> MlirDialectHandle;
    pub fn mlirGetDialectHandle__llvm__() -> MlirDialectHandle;

    pub fn mlirContextCreate() -> MlirContext;
    pub fn mlirContextCreateWithThreading(threading_enabled: bool) -> MlirContext;
    pub fn mlirContextCreateWithRegistry(
        registry: MlirDialectRegistry,
        threading_enabled: bool,
    ) -> MlirContext;
    pub fn mlirContextDestroy(context: MlirContext);
    pub fn mlirContextAppendDialectRegistry(context: MlirContext, registry: MlirDialectRegistry);
    pub fn mlirContextLoadAllAvailableDialects(context: MlirContext);
    pub fn mlirContextSetAllowUnregisteredDialects(context: MlirContext, allow: bool);
    pub fn mlirContextGetAllowUnregisteredDialects(context: MlirContext) -> bool;
    pub fn mlirContextGetNumRegisteredDialects(context: MlirContext) -> isize;
    pub fn mlirContextGetNumLoadedDialects(context: MlirContext) -> isize;
    pub fn mlirContextIsRegisteredOperation(context: MlirContext, name: MlirStringRef) -> bool;

    pub fn mlirIdentifierGet(context: MlirContext, string: MlirStringRef) -> MlirIdentifier;
    pub fn mlirIdentifierEqual(ident: MlirIdentifier, other: MlirIdentifier) -> bool;
    pub fn mlirIdentifierStr(ident: MlirIdentifier) -> MlirStringRef;

    pub fn mlirNamedAttributeGet(name: MlirIdentifier, attr: MlirAttribute) -> MlirNamedAttribute;

    pub fn mlirLocationGetContext(location: MlirLocation) -> MlirContext;
    pub fn mlirLocationFromAttribute(attribute: MlirAttribute) -> MlirLocation;
    pub fn mlirLocationGetAttribute(location: MlirLocation) -> MlirAttribute;
    pub fn mlirLocationUnknownGet(context: MlirContext) -> MlirLocation;
    pub fn mlirLocationFileLineColGet(
        context: MlirContext,
        filename: MlirStringRef,
        line: u32,
        col: u32,
    ) -> MlirLocation;
    pub fn mlirLocationPrint(
        location: MlirLocation,
        callback: MlirStringCallback,
        user_data: *mut c_void,
    );

    pub fn mlirModuleCreateEmpty(location: MlirLocation) -> MlirModule;
    pub fn mlirModuleCreateParse(context: MlirContext, module: MlirStringRef) -> MlirModule;
    pub fn mlirModuleCreateParseFromFile(
        context: MlirContext,
        file_name: MlirStringRef,
    ) -> MlirModule;
    pub fn mlirModuleGetContext(module: MlirModule) -> MlirContext;
    pub fn mlirModuleGetBody(module: MlirModule) -> MlirBlock;
    pub fn mlirModuleDestroy(module: MlirModule);
    pub fn mlirModuleGetOperation(module: MlirModule) -> MlirOperation;
    pub fn mlirModuleFromOperation(op: MlirOperation) -> MlirModule;

    pub fn mlirOperationStateGet(name: MlirStringRef, loc: MlirLocation) -> MlirOperationState;
    pub fn mlirOperationStateAddResults(
        state: *mut MlirOperationState,
        n: isize,
        results: *const MlirType,
    );
    pub fn mlirOperationStateAddOperands(
        state: *mut MlirOperationState,
        n: isize,
        operands: *const MlirValue,
    );
    pub fn mlirOperationStateAddOwnedRegions(
        state: *mut MlirOperationState,
        n: isize,
        regions: *const MlirRegion,
    );
    pub fn mlirOperationStateAddSuccessors(
        state: *mut MlirOperationState,
        n: isize,
        successors: *const MlirBlock,
    );
    pub fn mlirOperationStateAddAttributes(
        state: *mut MlirOperationState,
        n: isize,
        attributes: *const MlirNamedAttribute,
    );
    pub fn mlirOperationStateEnableResultTypeInference(state: *mut MlirOperationState);

    pub fn mlirOperationCreate(state: *mut MlirOperationState) -> MlirOperation;
    pub fn mlirOperationCreateParse(
        context: MlirContext,
        source_str: MlirStringRef,
        source_name: MlirStringRef,
    ) -> MlirOperation;
    pub fn mlirOperationClone(op: MlirOperation) -> MlirOperation;
    pub fn mlirOperationDestroy(op: MlirOperation);
    pub fn mlirOperationVerify(op: MlirOperation) -> MlirLogicalResult;
    pub fn mlirOperationGetContext(op: MlirOperation) -> MlirContext;
    pub fn mlirOperationGetLocation(op: MlirOperation) -> MlirLocation;
    pub fn mlirOperationSetLocation(op: MlirOperation, loc: MlirLocation);
    pub fn mlirOperationGetName(op: MlirOperation) -> MlirIdentifier;
    pub fn mlirOperationGetBlock(op: MlirOperation) -> MlirBlock;
    pub fn mlirOperationGetParentOperation(op: MlirOperation) -> MlirOperation;
    pub fn mlirOperationGetNumRegions(op: MlirOperation) -> isize;
    pub fn mlirOperationGetRegion(op: MlirOperation, pos: isize) -> MlirRegion;
    pub fn mlirOperationGetNextInBlock(op: MlirOperation) -> MlirOperation;
    pub fn mlirOperationGetNumOperands(op: MlirOperation) -> isize;
    pub fn mlirOperationGetOperand(op: MlirOperation, pos: isize) -> MlirValue;
    pub fn mlirOperationSetOperand(op: MlirOperation, pos: isize, new_value: MlirValue);
    pub fn mlirOperationSetOperands(
        op: MlirOperation,
        n_operands: isize,
        operands: *const MlirValue,
    );
    pub fn mlirOperationGetNumResults(op: MlirOperation) -> isize;
    pub fn mlirOperationGetResult(op: MlirOperation, pos: isize) -> MlirValue;
    pub fn mlirOperationGetNumSuccessors(op: MlirOperation) -> isize;
    pub fn mlirOperationGetSuccessor(op: MlirOperation, pos: isize) -> MlirBlock;
    pub fn mlirOperationSetSuccessor(op: MlirOperation, pos: isize, block: MlirBlock);
    pub fn mlirOperationHasInherentAttributeByName(op: MlirOperation, name: MlirStringRef) -> bool;
    pub fn mlirOperationGetInherentAttributeByName(
        op: MlirOperation,
        name: MlirStringRef,
    ) -> MlirAttribute;
    pub fn mlirOperationSetInherentAttributeByName(
        op: MlirOperation,
        name: MlirStringRef,
        attr: MlirAttribute,
    );
    pub fn mlirOperationGetNumDiscardableAttributes(op: MlirOperation) -> isize;
    pub fn mlirOperationGetDiscardableAttribute(
        op: MlirOperation,
        pos: isize,
    ) -> MlirNamedAttribute;
    pub fn mlirOperationGetDiscardableAttributeByName(
        op: MlirOperation,
        name: MlirStringRef,
    ) -> MlirAttribute;
    pub fn mlirOperationSetDiscardableAttributeByName(
        op: MlirOperation,
        name: MlirStringRef,
        attr: MlirAttribute,
    );
    pub fn mlirOperationRemoveDiscardableAttributeByName(
        op: MlirOperation,
        name: MlirStringRef,
    ) -> bool;
    pub fn mlirOperationGetNumAttributes(op: MlirOperation) -> isize;
    pub fn mlirOperationGetAttribute(op: MlirOperation, pos: isize) -> MlirNamedAttribute;
    pub fn mlirOperationGetAttributeByName(op: MlirOperation, name: MlirStringRef)
    -> MlirAttribute;
    pub fn mlirOperationSetAttributeByName(
        op: MlirOperation,
        name: MlirStringRef,
        attr: MlirAttribute,
    );
    pub fn mlirOperationRemoveAttributeByName(op: MlirOperation, name: MlirStringRef) -> bool;
    pub fn mlirOperationPrint(
        op: MlirOperation,
        callback: MlirStringCallback,
        user_data: *mut c_void,
    );
    pub fn mlirOperationWriteBytecode(
        op: MlirOperation,
        callback: MlirStringCallback,
        user_data: *mut c_void,
    );

    pub fn mlirRegionCreate() -> MlirRegion;
    pub fn mlirRegionDestroy(region: MlirRegion);
    pub fn mlirRegionGetFirstBlock(region: MlirRegion) -> MlirBlock;
    pub fn mlirRegionAppendOwnedBlock(region: MlirRegion, block: MlirBlock);
    pub fn mlirRegionInsertOwnedBlockAfter(
        region: MlirRegion,
        reference: MlirBlock,
        block: MlirBlock,
    );
    pub fn mlirRegionInsertOwnedBlockBefore(
        region: MlirRegion,
        reference: MlirBlock,
        block: MlirBlock,
    );
    pub fn mlirRegionGetNextInOperation(region: MlirRegion) -> MlirRegion;
    pub fn mlirRegionTakeBody(target: MlirRegion, source: MlirRegion);

    pub fn mlirBlockCreate(
        n_args: isize,
        args: *const MlirType,
        locs: *const MlirLocation,
    ) -> MlirBlock;
    pub fn mlirBlockDestroy(block: MlirBlock);
    pub fn mlirBlockDetach(block: MlirBlock);
    pub fn mlirBlockGetParentOperation(block: MlirBlock) -> MlirOperation;
    pub fn mlirBlockGetParentRegion(block: MlirBlock) -> MlirRegion;
    pub fn mlirBlockGetNextInRegion(block: MlirBlock) -> MlirBlock;
    pub fn mlirBlockGetFirstOperation(block: MlirBlock) -> MlirOperation;
    pub fn mlirBlockGetTerminator(block: MlirBlock) -> MlirOperation;
    pub fn mlirBlockAppendOwnedOperation(block: MlirBlock, operation: MlirOperation);
    pub fn mlirBlockInsertOwnedOperationBefore(
        block: MlirBlock,
        reference: MlirOperation,
        operation: MlirOperation,
    );
    pub fn mlirBlockInsertOwnedOperationAfter(
        block: MlirBlock,
        reference: MlirOperation,
        operation: MlirOperation,
    );
    pub fn mlirBlockGetNumArguments(block: MlirBlock) -> isize;
    pub fn mlirBlockAddArgument(block: MlirBlock, ty: MlirType, loc: MlirLocation) -> MlirValue;
    pub fn mlirBlockGetArgument(block: MlirBlock, pos: isize) -> MlirValue;
    pub fn mlirBlockPrint(block: MlirBlock, callback: MlirStringCallback, user_data: *mut c_void);

    pub fn mlirValueIsABlockArgument(value: MlirValue) -> bool;
    pub fn mlirValueIsAOpResult(value: MlirValue) -> bool;
    pub fn mlirBlockArgumentGetOwner(value: MlirValue) -> MlirBlock;
    pub fn mlirBlockArgumentGetArgNumber(value: MlirValue) -> isize;
    pub fn mlirOpResultGetOwner(value: MlirValue) -> MlirOperation;
    pub fn mlirOpResultGetResultNumber(value: MlirValue) -> isize;
    pub fn mlirValueGetType(value: MlirValue) -> MlirType;
    pub fn mlirValueSetType(value: MlirValue, ty: MlirType);
    pub fn mlirValueGetLocation(value: MlirValue) -> MlirLocation;
    pub fn mlirValueGetContext(value: MlirValue) -> MlirContext;
    pub fn mlirValueReplaceAllUsesOfWith(of: MlirValue, with: MlirValue);
    pub fn mlirValuePrint(value: MlirValue, callback: MlirStringCallback, user_data: *mut c_void);

    pub fn mlirTypeParseGet(context: MlirContext, ty: MlirStringRef) -> MlirType;
    pub fn mlirTypeGetContext(ty: MlirType) -> MlirContext;
    pub fn mlirTypeEqual(t1: MlirType, t2: MlirType) -> bool;
    pub fn mlirTypePrint(ty: MlirType, callback: MlirStringCallback, user_data: *mut c_void);

    pub fn mlirIntegerTypeGet(context: MlirContext, bitwidth: u32) -> MlirType;
    pub fn mlirIntegerTypeSignedGet(context: MlirContext, bitwidth: u32) -> MlirType;
    pub fn mlirIntegerTypeUnsignedGet(context: MlirContext, bitwidth: u32) -> MlirType;
    pub fn mlirIndexTypeGet(context: MlirContext) -> MlirType;
    pub fn mlirFunctionTypeGet(
        context: MlirContext,
        num_inputs: isize,
        inputs: *const MlirType,
        num_results: isize,
        results: *const MlirType,
    ) -> MlirType;
    pub fn mlirFunctionTypeGetNumInputs(ty: MlirType) -> isize;
    pub fn mlirFunctionTypeGetInput(ty: MlirType, pos: isize) -> MlirType;
    pub fn mlirFunctionTypeGetNumResults(ty: MlirType) -> isize;
    pub fn mlirFunctionTypeGetResult(ty: MlirType, pos: isize) -> MlirType;

    pub fn mlirAttributeGetNull() -> MlirAttribute;
    pub fn mlirAttributeParseGet(context: MlirContext, attr: MlirStringRef) -> MlirAttribute;
    pub fn mlirAttributeGetContext(attr: MlirAttribute) -> MlirContext;
    pub fn mlirAttributeGetType(attr: MlirAttribute) -> MlirType;
    pub fn mlirAttributeEqual(a1: MlirAttribute, a2: MlirAttribute) -> bool;
    pub fn mlirAttributePrint(
        attr: MlirAttribute,
        callback: MlirStringCallback,
        user_data: *mut c_void,
    );
    pub fn mlirBoolAttrGet(context: MlirContext, value: i32) -> MlirAttribute;
    pub fn mlirAttributeIsABool(attr: MlirAttribute) -> bool;
    pub fn mlirBoolAttrGetValue(attr: MlirAttribute) -> bool;
    pub fn mlirIntegerAttrGet(ty: MlirType, value: i64) -> MlirAttribute;
    pub fn mlirAttributeIsAInteger(attr: MlirAttribute) -> bool;
    pub fn mlirIntegerAttrGetValueInt(attr: MlirAttribute) -> i64;
    pub fn mlirIntegerAttrGetValueSInt(attr: MlirAttribute) -> i64;
    pub fn mlirIntegerAttrGetValueUInt(attr: MlirAttribute) -> u64;
    pub fn mlirStringAttrGet(context: MlirContext, value: MlirStringRef) -> MlirAttribute;
    pub fn mlirAttributeIsAString(attr: MlirAttribute) -> bool;
    pub fn mlirStringAttrGetValue(attr: MlirAttribute) -> MlirStringRef;

    pub fn mlirPassManagerCreate(context: MlirContext) -> MlirPassManager;
    pub fn mlirPassManagerCreateOnOperation(
        context: MlirContext,
        anchor_op: MlirStringRef,
    ) -> MlirPassManager;
    pub fn mlirPassManagerDestroy(pass_manager: MlirPassManager);
    pub fn mlirPassManagerGetAsOpPassManager(pass_manager: MlirPassManager) -> MlirOpPassManager;
    pub fn mlirPassManagerRunOnOp(
        pass_manager: MlirPassManager,
        op: MlirOperation,
    ) -> MlirLogicalResult;
    pub fn mlirPassManagerEnableVerifier(pass_manager: MlirPassManager, enable: bool);
    pub fn mlirPassManagerEnableTiming(pass_manager: MlirPassManager);

    pub fn mlirOpPassManagerAddPipeline(
        pass_manager: MlirOpPassManager,
        pipeline_elements: MlirStringRef,
        callback: MlirStringCallback,
        user_data: *mut c_void,
    ) -> MlirLogicalResult;
    pub fn mlirPrintPassPipeline(
        pass_manager: MlirOpPassManager,
        callback: MlirStringCallback,
        user_data: *mut c_void,
    );

    pub fn mlirSymbolTableGetSymbolAttributeName() -> MlirStringRef;
    pub fn mlirSymbolTableGetVisibilityAttributeName() -> MlirStringRef;
    pub fn mlirSymbolTableCreate(operation: MlirOperation) -> MlirSymbolTable;
    pub fn mlirSymbolTableDestroy(symbol_table: MlirSymbolTable);
    pub fn mlirSymbolTableLookup(
        symbol_table: MlirSymbolTable,
        name: MlirStringRef,
    ) -> MlirOperation;
    pub fn mlirSymbolTableInsert(
        symbol_table: MlirSymbolTable,
        operation: MlirOperation,
    ) -> MlirAttribute;
    pub fn mlirSymbolTableErase(symbol_table: MlirSymbolTable, operation: MlirOperation);
}

pub fn logical_result_is_success(result: MlirLogicalResult) -> bool {
    result.value != 0
}
