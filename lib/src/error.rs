use core::num::NonZeroI32;

use wdk_sys::NTSTATUS;

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NtError(NonZeroI32);

impl NtError {
    pub fn new(value: NTSTATUS) -> Self {
        Self(NonZeroI32::new(value).unwrap())
    }
    
    pub fn code(&self) -> NTSTATUS {
        self.0.get()
    }
}

impl core::convert::From<NTSTATUS> for NtError {
    fn from(value: NTSTATUS) -> Self {
        NtError(NonZeroI32::new(value).unwrap())
    }
}

impl core::error::Error for NtError {}

impl core::fmt::Debug for NtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Status {{ {:X} }}", self.0)
    }
}
impl core::fmt::Display for NtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

/// convert a NTSTATUS to a Result
pub fn cvt(status: NTSTATUS) -> Result<(), NtError> {
    match status {
        STATUS_SUCCESS => Ok(()),
        _ => Err(status.into()),
    }
}