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
#[cfg(not(target_env = "sgx"))]
pub use minidow::MINIDOW_SECRET;

static mut SEALING_KEY: sgx_key_128bit_t = [0; 16];

extern crate sgx_types;
use sgx_types::{
    sgx_get_key, sgx_key_128bit_t, sgx_key_request_t, sgx_report_t, sgx_self_report, sgx_status_t,
    SGX_KEYPOLICY_MRSIGNER, SGX_KEYSELECT_SEAL, TSEAL_DEFAULT_FLAGSMASK, TSEAL_DEFAULT_MISCMASK,
};

extern crate sgx_rand;

#[no_mangle]
static SECRET: u64 = 0x1122334455667788;

#[no_mangle]
pub unsafe extern "C" fn spectre_test(measurement_array_addr: u64, off: u64) {
    minidow::access_memory_spectre(measurement_array_addr as usize, off as usize);
}

#[no_mangle]
pub unsafe extern "C" fn spectre_enclave() -> u64 {
    let rand = sgx_rand::random::<[u8; 32]>();
    let report = sgx_self_report();

    let mut key_req = sgx_key_request_t::default();
    key_req.key_id = core::mem::transmute(rand);
    key_req.cpu_svn = (*report).body.cpu_svn;
    key_req.cpu_svn = (*report).body.cpu_svn;
    key_req.config_svn = (*report).body.config_svn;
    key_req.key_name = SGX_KEYSELECT_SEAL;
    key_req.key_policy = SGX_KEYPOLICY_MRSIGNER;
    key_req.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    key_req.attribute_mask.xfrm = 0;
    key_req.misc_mask = TSEAL_DEFAULT_MISCMASK;

    let success = sgx_get_key(&key_req as *const _, &mut SEALING_KEY as *mut _);
    if success != sgx_status_t::SGX_SUCCESS {
        #[cfg(not(target_env = "sgx"))]
        std::println!("couldn't get the key !");
    }

    #[cfg(not(target_env = "sgx"))]
    std::println!(
        "0x{:x}",
        core::mem::transmute::<sgx_key_128bit_t, u128>(SEALING_KEY)
    );

    return &SEALING_KEY as *const _ as u64;
}

#[no_mangle]
pub extern "C" fn get_secret_addr() -> u64 {
    return &SECRET as *const _ as u64;
}
