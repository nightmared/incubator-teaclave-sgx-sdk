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

extern crate sgx_types;
use sgx_types::{
    sgx_aes_gcm_128bit_tag_t, sgx_get_key, sgx_key_128bit_t, sgx_key_id_t, sgx_key_request_t,
    sgx_rijndael128GCM_decrypt, sgx_rijndael128GCM_encrypt, sgx_self_report, sgx_status_t,
    SGX_KEYPOLICY_MRSIGNER, SGX_KEYSELECT_SEAL, SGX_SEAL_IV_SIZE, TSEAL_DEFAULT_FLAGSMASK,
    TSEAL_DEFAULT_MISCMASK,
};

extern crate sgx_rand;

static mut PRIVATE_KEY: sgx_key_128bit_t = [0; 16];
#[no_mangle]
static SECRET: u64 = 0x1122334455667788;

#[no_mangle]
pub unsafe extern "C" fn spectre_test(measurement_array_addr: u64, off: u64) {
    minidow::access_memory_spectre(measurement_array_addr as usize, off as usize);
}

#[no_mangle]
pub unsafe extern "C" fn get_key_addr() -> *const sgx_key_128bit_t {
    &PRIVATE_KEY as *const _
}

pub unsafe fn get_seal_key() -> (sgx_key_id_t, *const sgx_key_128bit_t) {
    let rand = sgx_rand::random::<[u8; core::mem::size_of::<sgx_key_id_t>()]>();

    let key_id = sgx_key_id_t { id: rand };

    return (key_id, get_seal_key_from_key_id(key_id.clone()));
}

pub unsafe fn get_seal_key_from_key_id(key_id: sgx_key_id_t) -> *const sgx_key_128bit_t {
    let report = sgx_self_report();

    let mut key_req = sgx_key_request_t::default();
    key_req.key_id = key_id;
    key_req.cpu_svn = (*report).body.cpu_svn;
    key_req.cpu_svn = (*report).body.cpu_svn;
    key_req.config_svn = (*report).body.config_svn;
    key_req.key_name = SGX_KEYSELECT_SEAL;
    key_req.key_policy = SGX_KEYPOLICY_MRSIGNER;
    key_req.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    key_req.attribute_mask.xfrm = 0;
    key_req.misc_mask = TSEAL_DEFAULT_MISCMASK;

    let success = sgx_get_key(&key_req as *const _, &mut PRIVATE_KEY as *mut _);
    if success != sgx_status_t::SGX_SUCCESS {
        #[cfg(not(target_env = "sgx"))]
        std::println!("[enclave] couldn't get a key!");
    }

    #[cfg(not(target_env = "sgx"))]
    std::println!(
        "[enclave] Private key value: 0x{:x}",
        core::mem::transmute::<sgx_key_128bit_t, u128>(PRIVATE_KEY)
    );

    return &PRIVATE_KEY as *const _;
}

#[no_mangle]
pub unsafe extern "C" fn custom_seal_data(
    buf: *const u8,
    buf_size: u32,
    out_buf: *mut u8,
    out_size: *mut u32,
    out_tag: *mut sgx_aes_gcm_128bit_tag_t,
) -> sgx_status_t {
    let (key_id, key) = get_seal_key();

    #[cfg(not(target_env = "sgx"))]
    std::println!("[enclave] key_id in seal: {:?}", key_id.id);

    let additional_data = &key_id.id[0] as *const u8;
    let additional_data_len = core::mem::size_of::<sgx_key_id_t>() as u32;

    *out_size = (buf_size as usize + additional_data_len as usize) as u32;

    let status = sgx_rijndael128GCM_encrypt(
        key,
        buf,
        buf_size,
        out_buf,
        &[0u8; SGX_SEAL_IV_SIZE] as *const u8,
        SGX_SEAL_IV_SIZE as u32,
        additional_data,
        additional_data_len,
        out_tag,
    );

    core::ptr::copy(
        additional_data,
        (out_buf as usize + buf_size as usize) as *mut u8,
        additional_data_len as usize,
    );

    status
}

#[no_mangle]
pub unsafe extern "C" fn custom_unseal_data(
    buf: *const u8,
    buf_size: u32,
    out_buf: *mut u8,
    tag: *const sgx_aes_gcm_128bit_tag_t,
) -> sgx_status_t {
    let key_id = (buf as usize + buf_size as usize) as *const sgx_key_id_t;

    #[cfg(not(target_env = "sgx"))]
    std::println!("[enclave] tag: {:?}", *tag);

    #[cfg(not(target_env = "sgx"))]
    std::println!("[enclave] key_id in unseal: {:?}", (*key_id).id);
    let key = get_seal_key_from_key_id(*key_id);

    let status = sgx_rijndael128GCM_decrypt(
        key,
        buf,
        buf_size,
        out_buf,
        &[0_u8; SGX_SEAL_IV_SIZE] as *const u8,
        SGX_SEAL_IV_SIZE as u32,
        &(*key_id).id[0] as *const u8,
        core::mem::size_of::<sgx_key_id_t>() as u32,
        tag,
    );

    status
}

#[no_mangle]
pub extern "C" fn get_secret_addr() -> u64 {
    return &SECRET as *const _ as u64;
}
