use wdk_sys::NTSTATUS;

#[derive(Clone, Copy)]
pub struct NtError(NTSTATUS);

impl NtError {
    pub fn code(&self) -> NTSTATUS {
        self.0
    }
}

impl core::convert::From<NTSTATUS> for NtError {
    fn from(value: NTSTATUS) -> Self {
        NtError(value)
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