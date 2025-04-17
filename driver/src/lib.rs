#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

const NOTEPAD: &[u8; 24] = b"n\0o\0t\0e\0p\0a\0d\0.\0e\0x\0e\0\0\0";

use core::ptr;

use wdk::{dbg_break, println};
use wdk_sys::{
    BOOLEAN, GENERIC_ALL, HANDLE, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT,
    ntddk::{PsRemoveCreateThreadNotifyRoutine, PsSetCreateThreadNotifyRoutine, wcsstr},
};

use rmtrd::{
    kernel::*,
    kobject::{self, FromProcess},
    thread::{MaliciousThread, ThreadType},
    utils,
};

extern "C" fn thread_notify_routine(process_id: HANDLE, thread_id: HANDLE, create: BOOLEAN) {
    if create == 0 {
        return;
    }

    if let Ok(process) = kobject::ProcessObjectRef::from_process_id(process_id) {
        if let Ok(process_handle) =
            kobject::KernelHandleRef::from_process(process.get(), GENERIC_ALL)
        {
            if let Some(process_image_path) = utils::get_process_image_path(process_handle.get()) {
                unsafe {
                    // check if target process is under protected
                    // TODO: using strategy rules to detect malware thread in protected processes
                    if process_image_path.Length > 0
                        && wcsstr(process_image_path.Buffer, NOTEPAD.as_ptr().cast())
                            == ptr::null_mut()
                    {
                        return;
                    }
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
