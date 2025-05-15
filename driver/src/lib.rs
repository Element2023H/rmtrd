#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

const NOTEPAD: &str = "notepad.exe";

extern crate alloc;

use ksync::{handle::{self, FromRawProcess}, kobject::{self, FromProcessId}};
use wdk::{dbg_break, paged_code, println};
use wdk_sys::{
    APC_LEVEL,
    BOOLEAN, GENERIC_READ, HANDLE, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, WCHAR,
    ntddk::{KeGetCurrentIrql, PsRemoveCreateThreadNotifyRoutine, PsSetCreateThreadNotifyRoutine},
};

use rmtrd::{
    kernel::*,
    thread::{MaliciousThread, ThreadType},
    utils,
};

fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
    s.to_lowercase().ends_with(&suffix.to_lowercase())
}

extern "C" fn thread_notify_routine(process_id: HANDLE, thread_id: HANDLE, create: BOOLEAN) {
    paged_code!();

    if create == 0 {
        return;
    }

    if let Ok(process) = kobject::ProcessObject::from_process_id(process_id) {
        if let Ok(process_handle) =
            handle::ObjectHandle::from_process(process.get(), GENERIC_READ)
        {
            if let Some(process_image_path) = utils::get_process_image_path(process_handle.get()) {
                // check if target process is under protected
                // TODO: using strategy rules to detect malware thread in protected processes
                if !ends_with_ignore_case(&process_image_path[..], NOTEPAD) {
                    return;
                }

                if let Some(mut thread) = MaliciousThread::detect(process_id, thread_id) {
                    match thread.thread_type() {
                        ThreadType::IllegalWithModule => thread.gracefully_exit(),
                        ThreadType::IllegalModuleless => thread.force_exit(),
                        _ => (),
                    }
                }
            }
        }
    }
}

#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let mut status: NTSTATUS = 0;

    #[cfg(debug_assertions)]
    {
        dbg_break();
        println!("driver started");
    }

    // disable integrity check
    unsafe {
        (*driver).DriverUnload = Some(driver_unload);

        let ldr_data = &mut *((*driver).DriverSection as PKLDR_DATA_TABLE_ENTRY);

        ldr_data.Flags |= 0x20;

        status = PsSetCreateThreadNotifyRoutine(Some(thread_notify_routine));
    }

    status
}

pub unsafe extern "C" fn driver_unload(driver: PDRIVER_OBJECT) {
    unsafe {
        let _ = PsRemoveCreateThreadNotifyRoutine(Some(thread_notify_routine));
    }
}
