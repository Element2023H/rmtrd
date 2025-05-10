use core::{mem, ops::Deref, ptr::{self, NonNull}};

use wdk::nt_success;
use wdk_sys::{
    _KPROCESS, _KTHREAD,
    _MODE::KernelMode,
    HANDLE, OBJ_KERNEL_HANDLE, PEPROCESS, PETHREAD, PVOID, PsProcessType, PsThreadType, ULONG,
    ntddk::{
        ObOpenObjectByPointer, ObReferenceObjectByHandle, ObfDereferenceObject,
        PsLookupProcessByProcessId, PsLookupThreadByThreadId, ZwClose,
    },
};

use crate::error::{NtError, cvt};

/// A owned kernel object wrapper
#[repr(transparent)]
pub struct KernelObject<T>(*mut T);

pub trait FromProcess {
    fn from_process_id(id: HANDLE) -> Result<KernelObject<_KPROCESS>, NtError>;
    fn from_process_handle(handle: HANDLE, access: u32) -> Result<KernelObject<_KPROCESS>, NtError>;
}

pub trait FromThread {
    fn from_thread_id(id: HANDLE) -> Result<KernelObject<_KTHREAD>, NtError>;
    fn from_thread_handle(id: HANDLE, access: u32) -> Result<KernelObject<_KTHREAD>, NtError>;
}

// specialize for type ObjectRef<_KPROCESS>
impl FromProcess for KernelObject<_KPROCESS> {
    fn from_process_id(id: HANDLE) -> Result<KernelObject<_KPROCESS>, NtError> {
        let mut value: PEPROCESS = ptr::null_mut();

        unsafe {
            let status = PsLookupProcessByProcessId(id, &mut value);

            if !nt_success(status) {
                return Err(NtError::from(status));
            }
        }

        Ok(KernelObject::<_KPROCESS>(value))
    }

    fn from_process_handle(h: HANDLE, access: u32) -> Result<KernelObject<_KPROCESS>, NtError> {
        let mut value: PVOID = ptr::null_mut();

        let status = unsafe {
            ObReferenceObjectByHandle(
                h,
                access,
                *PsProcessType,
                KernelMode as _,
                &mut value,
                ptr::null_mut(),
            )
        };

        if !nt_success(status) {
            return Err(NtError::from(status));
        }

        Ok(KernelObject::<_KPROCESS>(value.cast()))
    }
}

// specialize for type ObjectRef<_KTHREAD>
impl FromThread for KernelObject<_KTHREAD> {
    fn from_thread_id(id: HANDLE) -> Result<KernelObject<_KTHREAD>, NtError> {
        let mut value: PETHREAD = ptr::null_mut();

        unsafe {
            let status = PsLookupThreadByThreadId(id, &mut value);

            if !nt_success(status) {
                return Err(NtError::from(status));
            }
        }

        Ok(KernelObject::<_KTHREAD>(value))
    }

    fn from_thread_handle(h: HANDLE, access: u32) -> Result<KernelObject<_KTHREAD>, NtError> {
        let mut value: PVOID = ptr::null_mut();

        let status = unsafe {
            ObReferenceObjectByHandle(
                h,
                access,
                *PsThreadType,
                KernelMode as _,
                &mut value,
                ptr::null_mut(),
            )
        };

        if !nt_success(status) {
            return Err(NtError::from(status));
        }

        Ok(KernelObject::<_KTHREAD>(value.cast()))
    }
}

impl<T> KernelObject<T> {
    pub fn valid(&self) -> bool {
        self.0 != ptr::null_mut()
    }

    pub fn as_raw(&self) -> *mut T {
        self.0
    }

    pub fn release(&mut self) {
        unsafe {
            if !self.0.is_null() {
                ObfDereferenceObject(self.0 as PVOID);
                let _ = mem::replace(&mut self.0, ptr::null_mut());
            }
        }
    }
}

impl<T> Drop for KernelObject<T> {
    fn drop(&mut self) {
        self.release();
    }
}

impl From<PETHREAD> for KernelObject<_KTHREAD> {
    fn from(value: PETHREAD) -> Self {
        Self(value)
    }
}

impl From<PEPROCESS> for KernelObject<_KPROCESS> {
    fn from(value: PEPROCESS) -> Self {
        Self(value)
    }
}

pub type ProcessObject = KernelObject<_KPROCESS>;
pub type ThreadObject = KernelObject<_KTHREAD>;

impl Deref for ProcessObject {
    type Target = PEPROCESS;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for ThreadObject {
    type Target = PETHREAD;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A owned kernel handle wrapper
#[repr(transparent)]
pub struct KernelHandle(HANDLE);

impl KernelHandle {
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }

    pub fn from_process(process: PEPROCESS, access: ULONG) -> Result<Self, NtError> {
        let mut handle: HANDLE = ptr::null_mut();
        unsafe {
            cvt(ObOpenObjectByPointer(
                process.cast(),
                OBJ_KERNEL_HANDLE as _,
                ptr::null_mut(),
                access,
                *PsProcessType,
                KernelMode as _,
                &mut handle,
            ))
            .map(|_| Self(handle))
        }
    }

    pub fn from_thread(thread: PETHREAD, access: ULONG) -> Result<Self, NtError> {
        let mut handle: HANDLE = ptr::null_mut();

        unsafe {
            cvt(ObOpenObjectByPointer(
                thread.cast(),
                OBJ_KERNEL_HANDLE as _,
                ptr::null_mut(),
                access,
                *PsThreadType,
                KernelMode as _,
                &mut handle,
            ))
            .map(|_| Self (handle))
        }
    }
}

impl Deref for KernelHandle {
    type Target = HANDLE;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for KernelHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = ZwClose(self.0);
            }

            let _ = mem::replace(&mut self.0, ptr::null_mut());
        }
    }
}

pub mod test {
    use wdk::println;

    use crate::utils::ulong_to_handle;

    use super::*;

    pub fn test_kobject() {
        if let Ok(process) = ProcessObject::from_process_id(ulong_to_handle(4368)) {
            println!("get process: {:p}", process.as_raw());
        }

        if let Ok(thread) = ThreadObject::from_thread_id(ulong_to_handle(4372)) {
            println!("get thread: {:p}", thread.as_raw());
        }
    }
}
