use core::{cmp::Ordering, ptr, slice, time};

use alloc::{ffi::CString, string::String, vec::Vec};
use wdk_sys::{
    LIST_ENTRY32, PEPROCESS, PLIST_ENTRY, PLIST_ENTRY32, PVOID, ULONG, USHORT, ntddk::strlen,
};

use crate::{
    CONTAINING_RECORD,
    kernel::{PsGetProcessPeb, PsGetProcessWow64Process, RtlImageNtHeader},
    pe::{self, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64},
    peb::{LDR_DATA_TABLE_ENTRY32, PEB_LDR_DATA32},
    types::LDR_DATA_TABLE_ENTRY,
    utils::delay,
};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct LdrModuleEntry {
    pub DllBase: PVOID,
    pub SizeOfImage: ULONG,
    pub EntryPoint: PVOID,
    pub BaseDllName: String,
    pub FullDllName: String,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ExportDataEntry {
    pub Ordinal: USHORT,
    pub FuncName: CString,
    pub Forward: bool,
    pub ForwardName: CString,
    pub FuncAddress: PVOID,
}

impl Default for ExportDataEntry {
    fn default() -> Self {
        ExportDataEntry {
            Ordinal: 0,
            FuncName: CString::default(),
            Forward: false,
            ForwardName: CString::default(),
            FuncAddress: ptr::null_mut(),
        }
    }
}

pub fn get_user_ldrs_x64(process: PEPROCESS) -> Option<Vec<LdrModuleEntry>> {
    unsafe {
        let peb = PsGetProcessPeb(process);

        // no PEB
        if peb.is_null() {
            return None;
        }

        // return if it stll not ready
        if (*peb).Ldr.is_null() {
            return None;
        }

        let head = &(*(*peb).Ldr).InLoadOrderModuleList as *const _ as PLIST_ENTRY;

        let mut p_list_entry = (*head).Flink;

        let mut ldrs = Vec::<LdrModuleEntry>::new();

        // Search in InLoadOrderModuleList
        while p_list_entry != head {
            let p_entry = CONTAINING_RECORD!(p_list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            ldrs.push(LdrModuleEntry {
                DllBase: (*p_entry).DllBase as PVOID,
                SizeOfImage: (*p_entry).SizeOfImage,
                EntryPoint: (*p_entry).EntryPoint as PVOID,
                BaseDllName: String::from_utf16_lossy(slice::from_raw_parts(
                    (*p_entry).BaseDllName.Buffer as *const u16,
                    ((*p_entry).BaseDllName.Length / 2) as usize,
                )),
                FullDllName: String::from_utf16_lossy(slice::from_raw_parts(
                    (*p_entry).FullDllName.Buffer as *const u16,
                    ((*p_entry).FullDllName.Length / 2) as usize,
                )),
            });

            p_list_entry = (*p_list_entry).Flink;
        }

        Some(ldrs)
    }
}

pub fn get_user_ldrs_x86(process: PEPROCESS) -> Option<Vec<LdrModuleEntry>> {
    unsafe {
        let peb = PsGetProcessWow64Process(process);

        // return if it stll not ready
        if (*peb).Ldr == 0 {
            return None;
        }

        let ldr = &*((*peb).Ldr as *mut PEB_LDR_DATA32);
        let head = &ldr.InLoadOrderModuleList as *const LIST_ENTRY32 as PLIST_ENTRY32;

        let mut p_list_entry = (*head).Flink as PLIST_ENTRY32;

        let mut ldrs = Vec::<LdrModuleEntry>::new();

        // Search in InLoadOrderModuleList
        while p_list_entry != head {
            let p_entry =
                CONTAINING_RECORD!(p_list_entry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

            ldrs.push(LdrModuleEntry {
                DllBase: (*p_entry).DllBase as PVOID,
                SizeOfImage: (*p_entry).SizeOfImage,
                EntryPoint: (*p_entry).EntryPoint as PVOID,
                BaseDllName: String::from_utf16_lossy(slice::from_raw_parts(
                    (*p_entry).BaseDllName.Buffer as *const u16,
                    ((*p_entry).BaseDllName.Length / 2) as usize,
                )),
                FullDllName: String::from_utf16_lossy(slice::from_raw_parts(
                    (*p_entry).FullDllName.Buffer as *const u16,
                    ((*p_entry).FullDllName.Length / 2) as usize,
                )),
            });

            p_list_entry = (*p_list_entry).Flink as PLIST_ENTRY32;
        }

        Some(ldrs)
    }
}

pub fn get_user_ldrs(process: PEPROCESS) -> Option<Vec<LdrModuleEntry>> {
    let is_wow64 = unsafe { PsGetProcessWow64Process(process) } != ptr::null_mut();

    if !is_wow64 {
        get_user_ldrs_x64(process)
    } else {
        get_user_ldrs_x86(process)
    }
}

fn get_directory_data(module_base: PVOID, index: usize, is_wow64: bool) -> Option<(PVOID, usize)> {
    if module_base.is_null() {
        return None;
    }

    let header = unsafe { RtlImageNtHeader(module_base) };

    unsafe {
        if !is_wow64 {
            let dir = &(*(header as *const IMAGE_NT_HEADERS64))
                .OptionalHeader
                .DataDirectory[index];

            if dir.VirtualAddress == 0 {
                return None;
            }

            Some((
                (module_base as usize + dir.VirtualAddress as usize) as PVOID,
                dir.VirtualAddress as usize,
            ))
        } else {
            let dir = &(*(header as *const IMAGE_NT_HEADERS32))
                .OptionalHeader
                .DataDirectory[index];

            if dir.VirtualAddress == 0 {
                return None;
            }

            Some((
                (module_base as usize + dir.VirtualAddress as usize) as PVOID,
                dir.VirtualAddress as usize,
            ))
        }
    }
}

#[inline(always)]
fn rva2_va<T>(module_base: PVOID, rva: usize) -> *mut T {
    (module_base as usize + rva) as *mut T
}

pub fn get_module_exports(module_base: PVOID, is_wow64: bool) -> Option<Vec<ExportDataEntry>> {
    let r = get_directory_data(module_base, pe::IMAGE_DIRECTORY_ENTRY_EXPORT, is_wow64);

    if r.is_none() {
        return None;
    }

    let export_table = r.unwrap().0 as *const pe::IMAGE_EXPORT_DIRECTORY;

    let header = unsafe { RtlImageNtHeader(module_base) };

    unsafe {
        let ordinal = rva2_va::<u16>(module_base, (*export_table).AddressOfNameOrdinals as usize);
        let address = rva2_va::<u32>(module_base, (*export_table).AddressOfFunctions as usize);
        let name = rva2_va::<u32>(module_base, (*export_table).AddressOfNames as usize);

        let mut region_rva: u32 = 0;
        let mut region_size: u32 = 0;

        if !is_wow64 {
            let hdr64 = &*(header as *const IMAGE_NT_HEADERS64);

            region_rva =
                hdr64.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

            region_size = hdr64.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else {
            let hdr32 = &*(header as *const IMAGE_NT_HEADERS32);

            region_rva =
                hdr32.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

            region_size = hdr32.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }

        let mut exports: Vec<ExportDataEntry> = Vec::new();

        // Find all exports with valid names
        for i in 0..(*export_table).NumberOfNames {
            let n_ord = (*ordinal.add(i as usize)) + (*export_table).Base as u16;
            let mut psz_func_name: *const i8 = ptr::null();

            let mut entry = ExportDataEntry::default();

            psz_func_name =
                (module_base as *const u8).add(*name.add(i as usize) as usize) as *const i8;

            entry.FuncName = CString::new(slice::from_raw_parts(
                psz_func_name as *const u8,
                strlen(psz_func_name) as usize,
            ))
            .unwrap();

            let func_address = (module_base as *const u8)
                .add(*address.add(*ordinal.add(i as usize) as usize) as usize)
                as usize;

            entry.FuncAddress = func_address as _;

            // Check if it is a forward export entry
            if func_address >= (module_base as usize) + region_rva as usize
                && func_address < (module_base as usize) + (region_rva + region_size) as usize
            {
                entry.Forward = true;

                entry.ForwardName = CString::new(slice::from_raw_parts(
                    func_address as *const u8,
                    strlen(func_address as *const i8) as usize,
                ))
                .unwrap();

                entry.FuncAddress = ptr::null_mut();
            }

            exports.push(entry);
        }

        exports.sort_by(
            |left: &ExportDataEntry, right: &ExportDataEntry| -> Ordering {
                left.FuncName.cmp(&right.FuncName)
            },
        );

        Some(exports)
    }
}
