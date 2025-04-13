use core::{ops::Deref, ptr};

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

pub struct ObjectRef<T> {
    object: *mut T,
}

pub trait FromProcess {
    fn from_process_id(id: HANDLE) -> Result<ObjectRef<_KPROCESS>, NtError>;
    fn from_process_handle(handle: HANDLE, access: u32) -> Result<ObjectRef<_KPROCESS>, NtError>;
}

pub trait FromThread {
    fn from_thread_id(id: HANDLE) -> Result<ObjectRef<_KTHREAD>, NtError>;
    fn from_thread_handle(id: HANDLE, access: u32) -> Result<ObjectRef<_KTHREAD>, NtError>;
}

// specialize for type ObjectRef<_KPROCESS>
impl FromProcess for ObjectRef<_KPROCESS> {
    fn from_process_id(id: HANDLE) -> Result<ObjectRef<_KPROCESS>, NtError> {
        let mut value: PEPROCESS = ptr::null_mut();

        unsafe {
            let status = PsLookupProcessByProcessId(id, &mut value);

            if !nt_success(status) {
                return Err(NtError::from(status));
            }
        }

        Ok(ObjectRef::<_KPROCESS> { object: value })
    }

    fn from_process_handle(h: HANDLE, access: u32) -> Result<ObjectRef<_KPROCESS>, NtError> {
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

        Ok(ObjectRef::<_KPROCESS> { object: value as _ })
    }
}

// specialize for type ObjectRef<_KTHREAD>
impl FromThread for ObjectRef<_KTHREAD> {
    fn from_thread_id(id: HANDLE) -> Result<ObjectRef<_KTHREAD>, NtError> {
        let mut value: PETHREAD = ptr::null_mut();

        unsafe {
            let status = PsLookupThreadByThreadId(id, &mut value);

            if !nt_success(status) {
                return Err(NtError::from(status));
            }
        }

        Ok(ObjectRef::<_KTHREAD> { object: value as _ })
    }

    fn from_thread_handle(h: HANDLE, access: u32) -> Result<ObjectRef<_KTHREAD>, NtError> {
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

        Ok(ObjectRef::<_KTHREAD> { object: value as _ })
    }
}

impl<T> ObjectRef<T> {
    pub fn valid(&self) -> bool {
        self.object != ptr::null_mut()
    }

    pub fn as_raw(&self) -> *mut T {
        self.object
    }

    pub fn get(&self) -> *mut T {
        self.object
    }

    pub fn release(&mut self) {
        unsafe {
            if !self.object.is_null() {
                ObfDereferenceObject(self.object as PVOID);

                self.object = ptr::null_mut();
            }
        }
    }
}

impl<T> Drop for ObjectRef<T> {
    fn drop(&mut self) {
        self.release();
    }
}

impl From<PETHREAD> for ObjectRef<_KTHREAD> {
    fn from(value: PETHREAD) -> Self {
        Self { object: value }
    }
}

impl From<PEPROCESS> for ObjectRef<_KPROCESS> {
    fn from(value: PEPROCESS) -> Self {
        Self { object: value }
    }
}

pub type ProcessObjectRef = ObjectRef<_KPROCESS>;
pub type ThreadObjectRef = ObjectRef<_KTHREAD>;

impl Deref for ProcessObjectRef {
    type Target = PEPROCESS;
    fn deref(&self) -> &Self::Target {
        &self.object
    }
}

impl Deref for ThreadObjectRef {
    type Target = PETHREAD;
    fn deref(&self) -> &Self::Target {
        &self.object
    }
}

pub struct KernelHandleRef {
    handle: HANDLE,
}

impl KernelHandleRef {
    pub fn get(&self) -> HANDLE {
        self.handle
    }

    pub fn from_process(process: PEPROCESS, access: ULONG) -> Result<Self, NtError> {
        let mut handle: HANDLE = ptr::null_mut();
        unsafe {
            return cvt(ObOpenObjectByPointer(
                process.cast(),
                OBJ_KERNEL_HANDLE as _,
                ptr::null_mut(),
                access,
                *PsProcessType,
                KernelMode as _,
                &mut handle,
            ))
            .map(|_| Self { handle });
        }
    }

    pub fn from_thread(thread: PETHREAD, access: ULONG) -> Result<Self, NtError> {
        let mut handle: HANDLE = ptr::null_mut();

        unsafe {
            return cvt(ObOpenObjectByPointer(
                thread.cast(),
                OBJ_KERNEL_HANDLE as _,
                ptr::null_mut(),
                access,
                *PsThreadType,
                KernelMode as _,
                &mut handle,
            ))
            .map(|_| Self { handle });
        }
    }
}

impl Deref for KernelHandleRef {
    type Target = HANDLE;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Drop for KernelHandleRef {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = ZwClose(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

pub mod test {
    use wdk::println;

    use crate::utils::ulong_to_handle;

    use super::*;

    pub fn test_kobject() {
        if let Ok(process) = ProcessObjectRef::from_process_id(ulong_to_handle(4368)) {
            println!("get process: {:p}", process.as_raw());
        }

        if let Ok(thread) = ThreadObjectRef::from_thread_id(ulong_to_handle(4372)) {
            println!("get thread: {:p}", thread.as_raw());
        }
    }
}
