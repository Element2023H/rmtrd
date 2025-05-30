use alloc::{boxed::Box, string::String};
use core::{arch::asm, mem, ptr, slice, time};
use wdk::{nt_success, paged_code};
use wdk_sys::{
    _MODE::KernelMode,
    _POOL_TYPE::NonPagedPoolNx,
    _PROCESSINFOCLASS::ProcessImageFileName,
    APC_LEVEL, FALSE, HANDLE, LARGE_INTEGER, LONGLONG, PKTHREAD, PVOID, STATUS_BUFFER_TOO_SMALL,
    STATUS_INFO_LENGTH_MISMATCH, ULONG, UNICODE_STRING, WCHAR,
    ntddk::{KeDelayExecutionThread, KeGetCurrentIrql},
};

use crate::{allocator::ExAllocatePoolWithTag, kernel::ZwQueryInformationProcess};

#[inline(always)]
pub fn handle_to_ulong(h: HANDLE) -> ULONG {
    h as ULONG
}

#[inline(always)]
pub fn ulong_to_handle(l: ULONG) -> HANDLE {
    l as HANDLE
}

#[inline(always)]
pub fn read_gs_qword(offset: u64) -> u64 {
    let value: u64;
    unsafe {
        asm!(
            "mov {}, gs:[{}]",
            out(reg) value,
            in(reg) offset,
        );
    }
    value
}

#[macro_export]
macro_rules! CONTAINING_RECORD {
    ($address:expr, $type:path, $field:ident) => {
        ($address as usize - core::mem::offset_of!($type, $field)) as *mut $type
    };
}

pub fn KeGetCurrentThread() -> PKTHREAD {
    (read_gs_qword(0x188) as PVOID).cast()
}

pub fn get_process_image_path(handle: HANDLE) -> Option<String> {
    paged_code!();

    let mut length: u32 = 0;

    let mut status = unsafe {
        ZwQueryInformationProcess(
            handle,
            ProcessImageFileName as _,
            ptr::null_mut(),
            0,
            &mut length,
        )
    };

    if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL {
        let buffer = unsafe {
            ExAllocatePoolWithTag(NonPagedPoolNx, length as _, u32::from_ne_bytes(*b"xxxx"))
        } as *mut UNICODE_STRING;

        if buffer.is_null() {
            return None;
        }

        let mut info = unsafe { Box::from_raw(buffer) };

        info.Length = (length as usize - mem::size_of::<UNICODE_STRING>()) as u16;
        info.MaximumLength = info.Length;
        info.Buffer = unsafe {
            (info.as_ref() as *const _ as *const u8).add(mem::size_of::<UNICODE_STRING>())
        } as *mut u16;

        status = unsafe {
            ZwQueryInformationProcess(
                handle,
                ProcessImageFileName as _,
                info.as_mut() as *mut _ as PVOID,
                length,
                ptr::null_mut(),
            )
        };

        // NOTE:
        // ZwQueryInformationProcess may return STATUS_SUCCESS with an empty unicode string
        if nt_success(status) && info.Length > 0 {
            let ret = String::from_utf16_lossy(unsafe {
                slice::from_raw_parts(info.Buffer, info.Length as usize / mem::size_of::<WCHAR>())
            });

            return Some(ret);
        }
    }

    None
}

#[macro_export]
macro_rules! rtl_constant_string {
    ($utf16:expr) => {
        wdk_sys::UNICODE_STRING {
            Length: $utf16.len() as u16,
            MaximumLength: $utf16.len() as u16,
            Buffer: $utf16.as_ptr() as *mut _,
        }
    };
}

pub fn delay(ms: time::Duration) {
    let mut timeout = LARGE_INTEGER::default();

    timeout.QuadPart = (-(ms.as_millis() as LONGLONG)) * 1000;

    unsafe {
        let _ = KeDelayExecutionThread(KernelMode as _, FALSE as _, &mut timeout);
    }
}
