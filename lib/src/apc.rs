use core::{mem, ptr};

use alloc::boxed::Box;
use wdk_sys::_MODE::{KernelMode, UserMode};
use wdk_sys::ntddk::{PsIsThreadTerminating, PsWrapApcWow64Thread};
use wdk_sys::{KAPC, PETHREAD, PKAPC, PVOID, STATUS_INVALID_PARAMETER};

use crate::{
    error::*,
    kernel::{
        KAPC_ENVIRONMENT, KeInitializeApc, KeInsertQueueApc, KeTestAlertThread, PKNORMAL_ROUTINE,
        PsGetCurrentProcessWow64Process, allocate_pool_nonpaged,
    },
    utils::KeGetCurrentThread,
};

#[unsafe(no_mangle)]
unsafe extern "C" fn KernelApcInjectCallback(
    Apc: PKAPC,
    NormalRoutine: PKNORMAL_ROUTINE,
    NormalContext: *mut PVOID,
    SystemArgument1: *mut PVOID,
    SystemArgument2: *mut PVOID,
) {
    unsafe {
        // Skip execution
        if PsIsThreadTerminating(KeGetCurrentThread() as _) != 0 {
            *(NormalRoutine as *mut PVOID) = ptr::null_mut();
        }

        if PsGetCurrentProcessWow64Process() != ptr::null_mut() {
            let _ = PsWrapApcWow64Thread(NormalContext, NormalRoutine as *mut PVOID);
        }

        // free the APC memory
        let _ = Box::from_raw(Apc);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn KernelApcPrepareCallback(
    Apc: PKAPC,
    NormalRoutine: PKNORMAL_ROUTINE,
    NormalContext: *mut PVOID,
    SystemArgument1: *mut PVOID,
    SystemArgument2: *mut PVOID,
) {
    unsafe {
        KeTestAlertThread(UserMode as _);

        // free the APC memory
        let _ = Box::from_raw(Apc);
    }
}

pub fn queue_user_apc(
    thread: PETHREAD,
    user_func: PVOID,
    arg1: PVOID,
    arg2: PVOID,
    arg3: PVOID,
    force: bool,
) -> Result<(), NtError> {
    if thread.is_null() {
        return Err(STATUS_INVALID_PARAMETER.into());
    }

    let mut prepare_apc: Box<KAPC> = Box::default();

    let mut inject_apc = allocate_pool_nonpaged::<KAPC>(mem::size_of::<KAPC>())?;

    unsafe {
        KeInitializeApc(
            inject_apc.as_mut(),
            thread,
            KAPC_ENVIRONMENT::OriginalApcEnvironment,
            Some(KernelApcInjectCallback),
            None,
            Some(mem::transmute(user_func)),
            UserMode as _,
            arg1,
        );

        if force {
            prepare_apc = allocate_pool_nonpaged::<KAPC>(mem::size_of::<KAPC>())?;

            KeInitializeApc(
                prepare_apc.as_mut(),
                thread,
                KAPC_ENVIRONMENT::OriginalApcEnvironment,
                Some(KernelApcPrepareCallback),
                None,
                None,
                KernelMode as _,
                ptr::null_mut(),
            );
        }

        // Insert APC
        if KeInsertQueueApc(inject_apc.as_mut(), arg2, arg3, 0) != 0 {
            if force {
                KeInsertQueueApc(prepare_apc.as_mut(), ptr::null_mut(), ptr::null_mut(), 0);

                mem::forget(prepare_apc);
            }

            mem::forget(inject_apc);
        }
    }

    Ok(())
}
