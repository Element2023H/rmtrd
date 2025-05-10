use core::{
    mem::{self},
    ptr, usize,
};

use alloc::ffi::CString;
use wdk::{nt_success, paged_code, println};
use wdk_sys::{
    _LOCK_OPERATION::IoReadAccess,
    _MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
    _MM_PAGE_PRIORITY::NormalPagePriority,
    _MODE::UserMode,
    _THREADINFOCLASS::ThreadQuerySetWin32StartAddress,
    APC_LEVEL, GENERIC_ALL, HANDLE, KAPC_STATE, MEMORY_BASIC_INFORMATION, MmHighestUserAddress,
    PAGE_EXECUTE_READWRITE, PAGE_SIZE, PVOID, ULONG_PTR,
    ntddk::{
        IoAllocateMdl, IoFreeMdl, KeGetCurrentIrql, KeStackAttachProcess, KeUnstackDetachProcess,
        MmProbeAndLockProcessPages, MmUnlockPages, ZwQueryVirtualMemory,
    },
};

use crate::{
    apc::queue_user_apc,
    kernel::{
        MmGetSystemAddressForMdlSafe, PsGetProcessWow64Process, ZwQueryInformationThread,
        allocate_virtual_memory,
    },
    kobject::{self, *},
    ldr, pe,
    utils::ulong_to_handle,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreadType {
    None,

    // legal thread
    Legal,

    // illegal thread start from within a known dll
    IllegalWithModule,

    // illegal thread start from a wild address
    IllegalModuleless,
}

pub struct MaliciousThread {
    is_wow64: bool,
    attached: bool,
    thread_type: ThreadType,
    apc_state: KAPC_STATE,
    process: kobject::ProcessObject,
    thread: kobject::ThreadObject,
    process_handle: kobject::KernelHandle,
    thread_handle: kobject::KernelHandle,
}

impl MaliciousThread {
    pub fn thread_type(&self) -> ThreadType {
        self.thread_type
    }

    pub fn detect(process_id: HANDLE, thread_id: HANDLE) -> Option<Self> {
        paged_code!();

        if process_id == ulong_to_handle(4) {
            return None;
        }

        let process = kobject::ProcessObject::from_process_id(process_id).ok()?;
        let process_handle =
            kobject::KernelHandle::from_process(process.as_raw(), GENERIC_ALL).ok()?;
        let thread = kobject::ThreadObject::from_thread_id(thread_id).ok()?;
        let thread_handle =
            kobject::KernelHandle::from_thread(thread.as_raw(), GENERIC_ALL).ok()?;

        let is_wow64 = unsafe { PsGetProcessWow64Process(process.as_raw()) } != ptr::null_mut();

        let mut this = Self {
            process,
            thread,
            process_handle,
            thread_handle,
            is_wow64,
            attached: false,
            thread_type: ThreadType::Legal,
            apc_state: KAPC_STATE::default(),
        };

        this._detect();

        match this.thread_type {
            ThreadType::IllegalModuleless | ThreadType::IllegalWithModule => Some(this),
            _ => None,
        }
    }

    /// detect if a thread is a remote suspicious thread
    fn _detect(&mut self) {
        unsafe { KeStackAttachProcess(self.process.as_raw(), &mut self.apc_state) };

        self.attached = true;

        self.thread_type = self.validate_thread();
    }

    /// Perform PE image header validation
    ///
    /// - header fields validation
    /// - PE magic validation
    /// - PE machine type validation
    /// - entry point address validation
    /// - image directories validation
    fn verify_pe_header(&self, header: PVOID) -> bool {
        let dos_header = unsafe { &*(header as *const pe::IMAGE_DOS_HEADER) };

        if dos_header.e_magic != 0x5a4d {
            return false;
        }

        if dos_header.e_lfanew == 0 {
            return false;
        }

        if dos_header.e_lfanew > PAGE_SIZE as _ {
            return false;
        }

        let nt_header = unsafe {
            &*((header as *const u8).wrapping_add(dos_header.e_lfanew as _)
                as *const pe::IMAGE_NT_HEADERS64)
        };

        let nt_header32 = unsafe {
            &*((header as *const u8).wrapping_add(dos_header.e_lfanew as _)
                as *const pe::IMAGE_NT_HEADERS32)
        };

        if nt_header.FileHeader.NumberOfSections < 2
            || nt_header.FileHeader.SizeOfOptionalHeader == 0
        {
            return false;
        }

        if nt_header.OptionalHeader.Magic != pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC
            && nt_header.OptionalHeader.Magic != pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC
        {
            return false;
        }

        // DO NOT check the EntryPoint field here, since it may be null
        // but we must check it later if it is not
        if nt_header.OptionalHeader.BaseOfCode < PAGE_SIZE
            || nt_header.OptionalHeader.ImageBase == 0
            || nt_header.OptionalHeader.MajorLinkerVersion == 0
        {
            return false;
        }

        let mut image_base = 0usize;
        let mut image_size = 0usize;
        let code_base = nt_header.OptionalHeader.BaseOfCode;

        if !self.is_wow64 {
            image_base = nt_header.OptionalHeader.ImageBase as usize;
            image_size = nt_header.OptionalHeader.SizeOfImage as usize;
        } else {
            image_base = nt_header.OptionalHeader.ImageBase as usize;
            image_size = nt_header32.OptionalHeader.SizeOfImage as usize;
        }

        if image_size == 0 {
            return false;
        }

        let mut entry_point = nt_header.OptionalHeader.AddressOfEntryPoint as usize;

        if entry_point != 0 {
            entry_point = entry_point + image_base as usize;

            // check if entry point inside a valid image range
            if !(entry_point > image_base && entry_point < image_base + image_size) {
                return false;
            }
        }

        // check if the directories RVA is in a valid image range
        // we only check the export directory
        let validate_dir = |id: usize, is_wow64: bool| -> bool {
            if !is_wow64 {
                let dir = &nt_header.OptionalHeader.DataDirectory[id];

                if dir.VirtualAddress > 0 && (dir.Size as usize) < image_size {
                    return true;
                }
            } else {
                let dir = &nt_header32.OptionalHeader.DataDirectory[id];

                if dir.VirtualAddress > 0 && (dir.Size as usize) < image_size {
                    return true;
                }
            }

            false
        };

        // we assume a valid module must have a valid reloc image directory
        validate_dir(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC, self.is_wow64)
    }

    /// validate the thread start address to see if it is relative to malware
    fn validate_thread(&self) -> ThreadType {
        paged_code!();

        let mut start_address: PVOID = ptr::null_mut();

        let mut status = unsafe {
            ZwQueryInformationThread(
                self.thread_handle.as_raw(),
                ThreadQuerySetWin32StartAddress as _,
                &mut start_address as *mut _ as PVOID,
                mem::size_of::<ULONG_PTR>() as _,
                ptr::null_mut(),
            )
        };

        if !nt_success(status) {
            return ThreadType::Legal;
        }

        let mut mem_info = MEMORY_BASIC_INFORMATION::default();

        // FIXME: ZwQueryInformationThread is not exported by ntoskrnl across all version of windows kernel
        // it is preferred to use MmGetSystemRoutine to obtain the function address from SSDT when it is not exported by ntoskrnl.exe
        status = unsafe {
            ZwQueryVirtualMemory(
                self.process_handle.as_raw(),
                start_address,
                MemoryBasicInformation,
                &mut mem_info as *mut _ as PVOID,
                mem::size_of_val(&mut mem_info) as u64,
                ptr::null_mut(),
            )
        };

        if !nt_success(status) {
            return ThreadType::Legal;
        }

        // FIXME: check if the start address is obfuscated with a unmeaningful value
        // MmIsAddressValid will return FALSE when the main thread is just inserted at this point
        // since the executable region is paged out
        if start_address.is_null() {
            return ThreadType::IllegalWithModule;
        }

        // illegal thread address outside of a PE module
        if !self.verify_pe_header(mem_info.AllocationBase) {
            #[cfg(debug_assertions)]
            println!("illegal thread start address at: {:p}", start_address);

            return ThreadType::IllegalModuleless;
        }

        // start address is inside a PE module
        // check if it contains a instruction tramplion
        if !self.is_wow64 {
            // case 1: jmp rcx, a instruction tramplion on x64
            if unsafe { (start_address as *const u16).read_unaligned() } == 0xe1ff {
                return ThreadType::IllegalModuleless;
            }
        } else {
            // case 2: jmp [esp + 4] / call [esp + 4], instruction tramplions on x86
            if unsafe { (start_address as *const u32).read_unaligned() } == 0x042464ff
                || unsafe { (start_address as *const u32).read_unaligned() } == 0x042454ff
            {
                return ThreadType::IllegalModuleless;
            }

            // more cases here...
        }

        // normal remote thread injection
        // check if start address is pointed to kernel32.dll-> LoadLibraryA/LoadLibraryW
        if let Some(ldrs) = ldr::get_user_ldrs(self.process.as_raw()) {
            if let Some(dll) = ldrs
                .iter()
                .find(|x| x.BaseDllName.eq_ignore_ascii_case("kernel32.dll"))
            {
                let r = ldr::get_module_exports(dll.DllBase, self.is_wow64);

                if r.is_some() {
                    let found = r
                        .unwrap()
                        .iter()
                        .filter(|x| {
                            x.FuncName == CString::new("LoadLibraryA").unwrap()
                                || x.FuncName == CString::new("LoadLibraryW").unwrap()
                        })
                        .map(|x| x.FuncAddress)
                        .any(|x| x == start_address);

                    if found {
                        #[cfg(debug_assertions)]
                        println!(
                            "illegal thread start address in kernel32.dll: {:p}",
                            start_address
                        );

                        return ThreadType::IllegalWithModule;
                    }
                }
            }

            // check if start address is pointed to kernelbase.dll-> LoadLibraryA/LoadLibraryW
            if let Some(dll) = ldrs
                .iter()
                .find(|x| x.BaseDllName.eq_ignore_ascii_case("kernelbase.dll"))
            {
                let r = ldr::get_module_exports(dll.DllBase, self.is_wow64);

                if r.is_some() {
                    let found = r
                        .unwrap()
                        .iter()
                        .filter(|x| {
                            x.FuncName == CString::new("LoadLibraryA").unwrap()
                                || x.FuncName == CString::new("LoadLibraryW").unwrap()
                        })
                        .map(|x| x.FuncAddress)
                        .any(|x| x == start_address);

                    if found {
                        #[cfg(debug_assertions)]
                        println!(
                            "illegal thread start address in kernelbase.dll: {:p}",
                            start_address
                        );

                        return ThreadType::IllegalWithModule;
                    }
                }
            }
        }

        ThreadType::Legal
    }

    /// queue an APC to thread to make thread exit gracefully
    ///
    /// this is typically implemented by calling `RtlExitUserThread` </br>
    ///
    /// NOTE: this method will not work when detection result is `IllegalModuleless`
    pub fn gracefully_exit(&mut self) {
        paged_code!();

        if self.thread_type <= ThreadType::Legal {
            return;
        }

        if let Ok(mem) = allocate_virtual_memory(usize::MAX as HANDLE, 16, PAGE_EXECUTE_READWRITE) {
            if let Some(ldrs) = ldr::get_user_ldrs(self.process.as_raw()) {
                if let Some(dll) = ldrs
                    .iter()
                    .find(|x| x.BaseDllName.eq_ignore_ascii_case("ntdll.dll"))
                {
                    if let Some(exports) = ldr::get_module_exports(dll.DllBase, self.is_wow64) {
                        if let Some(entry) = exports
                            .binary_search_by(|x| {
                                x.FuncName.cmp(&CString::new("RtlExitUserThread").unwrap())
                            })
                            .ok()
                            .and_then(|x| exports.get(x))
                        {
                            if !self.is_wow64 {
                                // mov rax, 0 -> ExitThread
                                // call rax
                                let mut code: [u8; 12] = [
                                    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0xFF, 0xD0,
                                ];

                                unsafe {
                                    (&mut code[2] as *mut u8 as *mut usize)
                                        .write_unaligned(entry.FuncAddress as usize);
                                    ptr::copy_nonoverlapping(code.as_ptr(), mem, code.len());
                                }
                            } else {
                                let mut code: [u8; 7] = [0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0];

                                unsafe {
                                    (&mut code[2] as *mut u8 as *mut u32)
                                        .write_unaligned(entry.FuncAddress as u32);
                                    ptr::copy_nonoverlapping(code.as_ptr(), mem, code.len());
                                }
                            }

                            let _ = queue_user_apc(
                                self.thread.as_raw(),
                                mem.cast(),
                                ptr::null_mut(),
                                ptr::null_mut(),
                                ptr::null_mut(),
                                false,
                            );
                        }
                    }
                }
            }
        }

        self.thread_type = ThreadType::None;
    }

    /// force the thread exit by patching the startup code of the thread
    pub fn force_exit(&mut self) {
        paged_code!();

        if self.thread_type <= ThreadType::Legal {
            return;
        }

        let mut start_address: PVOID = ptr::null_mut();

        unsafe {
            let status = ZwQueryInformationThread(
                self.thread_handle.as_raw(),
                ThreadQuerySetWin32StartAddress as _,
                &mut start_address as *mut _ as PVOID,
                mem::size_of::<ULONG_PTR>() as _,
                ptr::null_mut(),
            );

            // start interception
            // force the remote thread exit with exit status 0
            // furthermore, we can also insert a APC to force thread exit
            if nt_success(status)
                && !start_address.is_null()
                && start_address < MmHighestUserAddress
            {
                let mdl = IoAllocateMdl(start_address, PAGE_SIZE, 0, 0, ptr::null_mut());

                if !mdl.is_null() {
                    MmProbeAndLockProcessPages(
                        mdl,
                        self.process.as_raw(),
                        UserMode as _,
                        IoReadAccess,
                    );

                    let sys_va = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority as _);

                    if !sys_va.is_null() {
                        let code: [u8; 3] = [0x31, 0xC0, 0xC3];

                        ptr::copy_nonoverlapping(code.as_ptr(), sys_va as *mut u8, code.len());
                    }

                    MmUnlockPages(mdl);
                    IoFreeMdl(mdl);
                }
            }
        }

        self.thread_type = ThreadType::None;
    }
}

impl Drop for MaliciousThread {
    fn drop(&mut self) {
        if self.attached {
            unsafe {
                KeUnstackDetachProcess(&mut self.apc_state);
            }
        }
    }
}
