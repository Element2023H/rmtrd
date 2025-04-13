use wdk_sys::{LIST_ENTRY, LIST_ENTRY32, PVOID, UNICODE_STRING32};

#[repr(C)]
pub struct _PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: PVOID,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
}

pub type PEB_LDR_DATA = _PEB_LDR_DATA;
pub type PPEB_LDR_DATA = *mut _PEB_LDR_DATA;


#[repr(C)]
pub struct _PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Mutant: PVOID,
    pub ImageBaseAddress: PVOID,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: PVOID,
    pub SubSystemData: PVOID,
    pub ProcessHeap: PVOID,
    pub FastPebLock: PVOID,
    pub AtlThunkSListPtr: PVOID,
    pub IFEOKey: PVOID,
    pub CrossProcessFlags: PVOID,
    pub KernelCallbackTable: PVOID,
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: PVOID,
}

pub type PEB = _PEB;
pub type PPEB = *mut _PEB;

#[repr(C)]
pub struct _PEB32 {
    pub InheritedAddressSpace: u8,    // UCHAR corresponds to u8
    pub ReadImageFileExecOptions: u8, // UCHAR corresponds to u8
    pub BeingDebugged: u8,            // UCHAR corresponds to u8
    pub BitField: u8,                 // UCHAR corresponds to u8
    pub Mutant: u32,                  // ULONG corresponds to u32
    pub ImageBaseAddress: u32,        // ULONG corresponds to u32
    pub Ldr: u32,                     // ULONG corresponds to u32
    pub ProcessParameters: u32,       // ULONG corresponds to u32
    pub SubSystemData: u32,           // ULONG corresponds to u32
    pub ProcessHeap: u32,             // ULONG corresponds to u32
    pub FastPebLock: u32,             // ULONG corresponds to u32
    pub AtlThunkSListPtr: u32,        // ULONG corresponds to u32
    pub IFEOKey: u32,                 // ULONG corresponds to u32
    pub CrossProcessFlags: u32,       // ULONG corresponds to u32
    pub UserSharedInfoPtr: u32,       // ULONG corresponds to u32
    pub SystemReserved: u32,          // ULONG corresponds to u32
    pub AtlThunkSListPtr32: u32,      // ULONG corresponds to u32
    pub ApiSetMap: u32,               // ULONG corresponds to u32
}

pub type PEB32 = _PEB32;
pub type PPEB32 = *mut _PEB32;

#[repr(C)]
pub struct _PEB_LDR_DATA32 {
    pub Length: u32,                                   // ULONG corresponds to u32
    pub Initialized: u8,                               // UCHAR corresponds to u8
    pub SsHandle: u32,                                 // ULONG used in WOW64 corresponds to u32
    pub InLoadOrderModuleList: LIST_ENTRY32,           // LIST_ENTRY32 needs to be defined in Rust
    pub InMemoryOrderModuleList: LIST_ENTRY32,         // LIST_ENTRY32 needs to be defined in Rust
    pub InInitializationOrderModuleList: LIST_ENTRY32, // LIST_ENTRY32 needs to be defined in Rust
}

pub type PEB_LDR_DATA32 = _PEB_LDR_DATA32;
pub type PPEB_LDR_DATA32 = *mut _PEB_LDR_DATA32;

#[repr(C)]
pub struct _LDR_DATA_TABLE_ENTRY32 {
    pub InLoadOrderLinks: LIST_ENTRY32, // Matches LIST_ENTRY32 struct from C
    pub InMemoryOrderLinks: LIST_ENTRY32, // Matches LIST_ENTRY32 struct from C
    pub InInitializationOrderLinks: LIST_ENTRY32, // Matches LIST_ENTRY32 struct from C
    pub DllBase: u32,                   // ULONG corresponds to u32
    pub EntryPoint: u32,                // ULONG corresponds to u32
    pub SizeOfImage: u32,               // ULONG corresponds to u32
    pub FullDllName: UNICODE_STRING32,  // Matches UNICODE_STRING32 struct
    pub BaseDllName: UNICODE_STRING32,  // Matches UNICODE_STRING32 struct
    pub Flags: u32,                     // ULONG corresponds to u32
    pub LoadCount: u16,                 // USHORT corresponds to u16
    pub TlsIndex: u16,                  // USHORT corresponds to u16
    pub HashLinks: LIST_ENTRY32,        // Matches LIST_ENTRY32 struct from C
    pub TimeDateStamp: u32,             // ULONG corresponds to u32
}

pub type LDR_DATA_TABLE_ENTRY32 = _LDR_DATA_TABLE_ENTRY32;
pub type PLDR_DATA_TABLE_ENTRY32 = *mut _LDR_DATA_TABLE_ENTRY32;