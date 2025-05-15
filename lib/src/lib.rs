#![no_std]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[cfg(not(test))]
extern crate wdk_panic;

mod allocator;

use allocator::GlobalAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator;

extern crate alloc;

pub mod apc;
pub mod error;
pub mod kernel;
pub mod utils;
pub mod thread;

pub(crate) mod ldr;
pub(crate) mod pe;
pub(crate) mod peb;
pub(crate) mod types;