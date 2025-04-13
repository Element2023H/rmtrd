use core::{alloc::GlobalAlloc, ptr};

use wdk_sys::{
    ntddk::{memset, ExFreePoolWithTag}, POOL_TYPE, PVOID, SIZE_T, ULONG, _POOL_TYPE::{NonPagedPoolNx, PagedPool}
};

pub struct GlobalAllocator;

const RUST_TAG: ULONG = u32::from_ne_bytes(*b"rust");

unsafe extern "C" {
    pub fn ExAllocatePoolWithTag(pool_type: POOL_TYPE, size: SIZE_T, tag: ULONG) -> PVOID;
}

pub fn ex_allocate_pool_zero(pool_type: POOL_TYPE, size: SIZE_T, tag: ULONG) -> PVOID {
    let ptr = unsafe { ExAllocatePoolWithTag(pool_type, size, tag) };

    if !ptr.is_null() {
        unsafe { memset(ptr, 0, size) };
    }

    ptr
}

unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let ptr = ex_allocate_pool_zero(NonPagedPoolNx, layout.size() as u64, RUST_TAG);

        if ptr == ptr::null_mut() {
            return ptr::null_mut();
        }

        ptr.cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe { ExFreePoolWithTag(ptr.cast(), RUST_TAG) };
    }
}

// stable rust forbids to assgin an `Allocator` template parameter to Box
// type PagedBox<T> = alloc::boxed::Box<T, PagedAllocator>;
pub struct PagedAllocator;

const RUST_PAGED_TAG: ULONG = u32::from_ne_bytes(*b"egap");

impl PagedAllocator {
    pub fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let ptr = ex_allocate_pool_zero(PagedPool, layout.size() as u64, RUST_PAGED_TAG);

        if ptr == ptr::null_mut() {
            return ptr::null_mut();
        }

        ptr.cast()
    }

    pub fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe { ExFreePoolWithTag(ptr.cast(), RUST_PAGED_TAG) };
    }
}