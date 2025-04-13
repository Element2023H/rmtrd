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
pub mod kobject;
pub mod ldr;
pub mod pe;
pub mod peb;
pub mod types;
pub mod utils;
pub mod thread;