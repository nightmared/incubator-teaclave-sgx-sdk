// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "enclave1"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(llvm_asm)]

#[cfg(not(target_env = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(not(target_env = "sgx"))]
extern crate minidow;

pub use minidow::MINIDOW_SECRET;

#[no_mangle]
static SECRET: u64 = 0x1122334455667788;
static mut SHOWN: bool = false;

#[no_mangle]
pub unsafe extern "C" fn spectre_test(measurement_array_addr: u64, off: u64) {
    std::ptr::read_volatile(&SECRET as *const u64);
    //    std::ptr::read_volatile(
    //        (measurement_array_addr + 15 * minidow::MULTIPLE_OFFSET as u64) as *mut u8,
    //    );
    //if !SHOWN {
    //    #[cfg(not(target_env = "sgx"))]
    //    std::println!(
    //        "{:p}, 0x{:x}",
    //        &minidow::MINIDOW_SECRET[64] as *const _ as *const u8,
    //        off,
    //    );
    //    SHOWN = true;
    //}
    minidow::access_memory_spectre(measurement_array_addr as usize, off as usize);
}

#[no_mangle]
pub extern "C" fn spectre_enclave() -> u64 {
    #[cfg(not(target_env = "sgx"))]
    std::println!("{:p}", unsafe {
        &minidow::SPECTRE_LIMIT as *const _ as *const u8
    });
    return &SECRET as *const _ as u64;
}
