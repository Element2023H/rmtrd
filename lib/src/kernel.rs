use core::{
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

use alloc::boxed::Box;
use wdk::nt_success;
use wdk_sys::{
    _KPROCESS,
    _MEMORY_CACHING_TYPE::MmCached,
    _MODE::KernelMode,
    _POOL_TYPE::{NonPagedPoolNx, PagedPool},
    ACCESS_MASK, BOOLEAN, HANDLE, KPRIORITY, KPROCESSOR_MODE, MDL_MAPPED_TO_SYSTEM_VA,
    MDL_SOURCE_IS_NONPAGED_POOL, MEM_COMMIT, MEM_RESERVE, NTSTATUS, PEPROCESS, PHANDLE, PKAPC,
    PKTHREAD, PMDL, PULONG, PVOID, SIZE_T, STATUS_INSUFFICIENT_RESOURCES, ULONG,
    ntddk::{
        MmMapLockedPagesSpecifyCache, ObfDereferenceObject, PsLookupProcessByProcessId,
        ZwAllocateVirtualMemory,
    },
};

pub use crate::types::*;
use crate::{
    allocator::ExAllocatePoolWithTag,
    error::NtError,
    peb::{PPEB, PPEB32},
};

static PsInitialProcess: AtomicPtr<_KPROCESS> = AtomicPtr::new(ptr::null_mut());

// this function returns PsInitialSystemProcess
// the symbol PsInitialProcess can not be linked properly in this version of wdk-sys, don't know why
pub fn get_initial_system_process() -> PEPROCESS {
    unsafe {
        let mut process = PsInitialProcess.load(Ordering::Acquire);

        if !process.is_null() {
            return process;
        }

        let status = PsLookupProcessByProcessId(4 as _, &mut process);

        if nt_success(status) {
            let _ = PsInitialProcess.compare_exchange(
                ptr::null_mut(),
                process,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );

            // is safe to dereference here, since the PsInitialProcess is never destoryed before system shutdown
            ObfDereferenceObject(process.cast());

            return process;
        }
    }

    ptr::null_mut()
}

#[inline]
pub fn MmGetSystemAddressForMdlSafe(Mdl: PMDL, Priority: ULONG) -> PVOID {
    unsafe {
        if (*Mdl).MdlFlags as u32 & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) > 0 {
            (*Mdl).MappedSystemVa
        } else {
            MmMapLockedPagesSpecifyCache(
                Mdl,
                KernelMode as _,
                MmCached,
                ptr::null_mut(),
                0,
                Priority,
            )
        }
    }
}

const POOL_TAG: ULONG = u32::from_ne_bytes(*b"tfed");

pub fn allocate_pool_paged<T>(size: usize) -> Result<Box<T>, NtError> {
    let base = unsafe { ExAllocatePoolWithTag(PagedPool, size as _, POOL_TAG) as *mut T };

    if !base.is_null() {
        Ok(unsafe { Box::from_raw(base as *mut T) })
    } else {
        Err(NtError::from(STATUS_INSUFFICIENT_RESOURCES))
    }
}

pub fn allocate_pool_nonpaged<T>(size: usize) -> Result<Box<T>, NtError> {
    let base = unsafe { ExAllocatePoolWithTag(NonPagedPoolNx, size as _, POOL_TAG) as *mut T };

    if !base.is_null() {
        Ok(unsafe { Box::from_raw(base as *mut T) })
    } else {
        Err(NtError::from(STATUS_INSUFFICIENT_RESOURCES))
    }
}

pub fn allocate_virtual_memory(
    process: HANDLE,
    size: usize,
    protect: ULONG,
) -> Result<*mut u8, NtError> {
    let mut base: PVOID = ptr::null_mut();
    let mut region_size = size as SIZE_T;

    let status = unsafe {
        ZwAllocateVirtualMemory(
            process,
            &mut base,
            0,
            &mut region_size,
            MEM_RESERVE | MEM_COMMIT,
            protect,
        )
    };

    if nt_success(status) {
        return Ok(base as _);
    }

    Err(NtError::from(status))
}

// import functions
unsafe extern "C" {
    pub fn ZwQueryInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: ULONG,
        ThreadInformation: PVOID,
        ThreadInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;

    pub fn ZwQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: ULONG,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;

    pub fn ZwGetNextThread(
        ProcessHandle: HANDLE,
        ThreadHandle: HANDLE,
        DesiredAccess: ACCESS_MASK,
        HandleAttributes: ULONG,
        Flags: ULONG,
        NewThreadHandle: PHANDLE,
    ) -> NTSTATUS;

    pub fn KeInitializeApc(
        Apc: PKAPC,
        Thread: PKTHREAD,
        ApcStateIndex: KAPC_ENVIRONMENT,
        KernelRoutine: Option<PKKERNEL_ROUTINE>,
        RundownRoutine: Option<PKRUNDOWN_ROUTINE>,
        NormalRoutine: Option<PKNORMAL_ROUTINE>,
        ApcMode: KPROCESSOR_MODE,
        NormalContext: PVOID,
    );

    pub fn KeInsertQueueApc(
        Apc: PKAPC,
        SystemArgument1: PVOID,
        SystemArgument2: PVOID,
        Increment: KPRIORITY,
    ) -> BOOLEAN;

    pub fn KeTestAlertThread(AlertMode: KPROCESSOR_MODE) -> BOOLEAN;

    pub fn PsGetCurrentProcessWow64Process() -> PVOID;

    pub fn PsGetProcessPeb(Process: PEPROCESS) -> PPEB;

    pub fn PsGetProcessWow64Process(Process: PEPROCESS) -> PPEB32;

    pub fn RtlImageNtHeader(base: PVOID) -> PVOID;

    pub fn PsGetProcessSectionBaseAddress(Process: PEPROCESS) -> PVOID;
}
