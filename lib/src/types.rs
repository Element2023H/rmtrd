use wdk_sys::{LIST_ENTRY, PRKAPC, PVOID, UNICODE_STRING, _EPROCESS, _FILE_OBJECT, _LIST_ENTRY};

#[repr(C)]
pub struct KLDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub ExceptionTable: *mut core::ffi::c_void,
    pub ExceptionTableSize: u32,
    pub GpValue: *mut core::ffi::c_void,
    pub NonPagedDebugInfo: *mut core::ffi::c_void,
    pub DllBase: *mut core::ffi::c_void,
    pub EntryPoint: *mut core::ffi::c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: u32,
    pub LoadCount: u16,
    pub __Unused5: u16,
    pub SectionPointer: *mut core::ffi::c_void,
    pub CheckSum: u32,
    pub LoadedImports: *mut core::ffi::c_void,
    pub PatchInformation: *mut core::ffi::c_void,
}

pub type PKLDR_DATA_TABLE_ENTRY = *mut KLDR_DATA_TABLE_ENTRY;

#[repr(C)]
pub enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment,
}

pub type KAPC_ENVIRONMENT = _KAPC_ENVIRONMENT;
pub type PKAPC_ENVIRONMENT = *mut _KAPC_ENVIRONMENT;

pub type PKNORMAL_ROUTINE = unsafe extern "C" fn(PVOID, PVOID, PVOID);
pub type PKRUNDOWN_ROUTINE = unsafe extern "C" fn(PRKAPC);
pub type PKKERNEL_ROUTINE =
    unsafe extern "C" fn(PRKAPC, PKNORMAL_ROUTINE, *mut PVOID, *mut PVOID, *mut PVOID);

#[repr(C)]
pub struct _LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY, // Matches LIST_ENTRY struct from C
    pub InMemoryOrderLinks: LIST_ENTRY, // Matches LIST_ENTRY struct from C
    pub InInitializationOrderLinks: LIST_ENTRY, // Matches LIST_ENTRY struct from C
    pub DllBase: PVOID,               // PVOID remains unchanged
    pub EntryPoint: PVOID,            // PVOID remains unchanged
    pub SizeOfImage: u32,             // ULONG corresponds to u32
    pub FullDllName: UNICODE_STRING,  // Matches UNICODE_STRING struct
    pub BaseDllName: UNICODE_STRING,  // Matches UNICODE_STRING struct
    pub Flags: u32,                   // ULONG corresponds to u32
    pub LoadCount: u16,               // USHORT corresponds to u16
    pub TlsIndex: u16,                // USHORT corresponds to u16
    pub HashLinks: LIST_ENTRY,        // Matches LIST_ENTRY struct from C
    pub TimeDateStamp: u32,           // ULONG corresponds to u32
}

pub type LDR_DATA_TABLE_ENTRY = _LDR_DATA_TABLE_ENTRY;
pub type PLDR_DATA_TABLE_ENTRY = *mut _LDR_DATA_TABLE_ENTRY;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PointersStruct {
    pub Left: *mut _RTL_BALANCED_NODE,
    pub Right: *mut _RTL_BALANCED_NODE,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ChildrenOrPointersUnion {
    pub Children: [*mut _RTL_BALANCED_NODE; 2], // Array of two children
    pub Pointers: PointersStruct,              // Left and Right pointers
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union FlagsOrParentValueUnion {
    pub Red: u8,               // Bitfield, use manual bit masking for the lowest bit
    pub Balance: u8,           // Bitfield, use manual bit masking for the first two bits
    pub ParentValue: usize,    // ULONG_PTR equivalent
}

#[repr(C)]
pub union _EX_PUSH_LOCK {
    pub Flags: u64,                 // Struct for bitfields
    pub Value: u64,                 // Size=8 Offset=0
    pub Ptr: PVOID,                 // Size=8 Offset=0
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct _RTL_BALANCED_NODE {
    // Union for Children or Left/Right
    pub ChildrenOrPointers: ChildrenOrPointersUnion,

    // Union for Red, Balance, or ParentValue
    pub FlagsOrParentValue: FlagsOrParentValueUnion,
}

#[repr(C)]
pub union VadNodeOrNextVad {
    pub VadNode: _RTL_BALANCED_NODE,             // Size=24 Offset=0
    pub NextVad: *mut _MMVAD_SHORT,              // Size=8 Offset=0
}

#[repr(C)]
pub union ___unnamed1951 {
    pub LongFlags: u32,                          // Size=4 Offset=0
    pub VadFlags: u32,                           // Size=4 Offset=0
}

#[repr(C)]
pub union ___unnamed1952 {
    pub LongFlags1: u32,                         // Size=4 Offset=0
    pub VadFlags1: u32,                          // Size=4 Offset=0
}

#[repr(C)]
pub struct _MMVAD_SHORT {
    pub u1: VadNodeOrNextVad,                    // Anonymous union: _RTL_BALANCED_NODE or *mut _MMVAD_SHORT
    pub StartingVpn: u32,                        // Size=4 Offset=24
    pub EndingVpn: u32,                          // Size=4 Offset=28
    pub StartingVpnHigh: u8,                     // Size=1 Offset=32
    pub EndingVpnHigh: u8,                       // Size=1 Offset=33
    pub CommitChargeHigh: u8,                    // Size=1 Offset=34
    pub SpareNT64VadUChar: u8,                   // Size=1 Offset=35
    pub ReferenceCount: i32,                     // Size=4 Offset=36
    pub PushLock: _EX_PUSH_LOCK,                 // Size=8 Offset=40
    pub u2: ___unnamed1951,                      // Size=4 Offset=48
    pub u3: ___unnamed1952,                      // Size=4 Offset=52
    pub EventList: PVOID,                        // Size=8 Offset=56
}

#[repr(C)]
pub union ___unnamed2047 {
    pub LongFlags2: u32,                         // Size=4 Offset=0
    pub VadFlags2: u32,                          // Size=4 Offset=0
}

#[repr(C)]
pub union ___unnamed2048 {
    pub SequentialVa: u64,          // Size=8 Offset=0
    pub ExtendedInfo: PVOID,        // Size=8 Offset=0
}

#[repr(C)]
pub struct _MMVAD {
    pub Core: _MMVAD_SHORT,                      // Size=64 Offset=0
    pub u2: ___unnamed2047,                      // Size=4 Offset=64
    pub pad0: u32,                               // Size=4 Offset=68
    pub Subsection: PVOID,                       // Size=8 Offset=72
    pub FirstPrototypePte: PVOID,                // Size=8 Offset=80
    pub LastContiguousPte: PVOID,                // Size=8 Offset=88
    pub ViewLinks: _LIST_ENTRY,                  // Size=16 Offset=96
    pub VadsProcess: *mut _EPROCESS,             // Size=8 Offset=112
    pub u4: ___unnamed2048,                      // Size=8 Offset=120
    pub FileObject: *mut _FILE_OBJECT,           // Size=8 Offset=128
}

pub type MMVAD = _MMVAD;
pub type PMMVAD = *mut _MMVAD;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Balance {
    pub Balance: i64,                      // Size=8 Offset=0 BitOffset=0 BitCount=2
}

#[repr(C)]
pub union ___unnamed1666 {
    pub Balance: Balance,                  // Balance bitfield
    pub Parent: *mut _MM_AVL_NODE,         // Size=8 Offset=0
}

#[repr(C)]
pub struct _MM_AVL_NODE {
    pub LeftChild: *mut _MM_AVL_NODE,       // Size=8 Offset=0
    pub RightChild: *mut _MM_AVL_NODE,      // Size=8 Offset=8

    pub u1: ___unnamed1666,                 // Size=8
}

#[repr(C)]
pub struct _RTL_AVL_TREE {
    pub BalancedRoot: *mut _MM_AVL_NODE,        // Size=8
    pub NodeHint: *mut core::ffi::c_void,       // Size=8
    pub NumberGenericTableElements: u64,       // Size=8
}

pub type MM_AVL_NODE = _MM_AVL_NODE;
pub type PMM_AVL_NODE = *mut _MM_AVL_NODE;
pub type PMMADDRESS_NODE = *mut _MM_AVL_NODE;

pub type RTL_AVL_TREE = _RTL_AVL_TREE;
pub type PRTL_AVL_TREE = *mut _RTL_AVL_TREE;
pub type MM_AVL_TABLE = _RTL_AVL_TREE;
pub type PMM_AVL_TABLE = *mut _RTL_AVL_TREE;
