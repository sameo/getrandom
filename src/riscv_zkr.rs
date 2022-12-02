// Copyright 2018 Developers of the Rand project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Zkr extension Implementation for bare metal RISC-V.
use crate::{slice_assume_init_mut, Error};
use core::{arch::asm, mem::MaybeUninit};

use hmac_drbg::HmacDRBG;
use sha2::Sha256;

const CSR_SEED: u16 = 0x015;

const SEED_OPST_MASK: u32 = 0xC000_0000;
const SEED_OPST_ES16: u32 = 0x8000_0000;
const SEED_ENTROPY_MASK: u32 = 0xffff;
const ENTROPY_BYTES: usize = 128;

pub fn getrandom_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    let mut retry = 10;
    let mut entropy_bytes: [u8; ENTROPY_BYTES] = [0; ENTROPY_BYTES];
    let mut index = 0;

    while retry > 0 {
        let r: u32;

        unsafe {
            asm!("csrrw {rd}, {csr}, x0", rd = out(reg) r, csr = const CSR_SEED);
        }

        if r & SEED_OPST_MASK != SEED_OPST_ES16 {
            retry -= 1;
            continue;
        }

        let entropy: u16 = (r & SEED_ENTROPY_MASK) as u16;
        let entropy_l: u8 = (entropy >> 8) as u8;
        let entropy_h: u8 = ((entropy & 0xff00) >> 8) as u8;

        if let Some(b) = entropy_bytes.get_mut(index + 1) {
            *b = entropy_h;
        }

        if let Some(b) = entropy_bytes.get_mut(index) {
            *b = entropy_l;
        }

        index += 2;

        if index == ENTROPY_BYTES {
            break;
        }
    }

    if retry == 0 {
        return Err(Error::RISCV_ZKR_RANDOM);
    }

    let mut drbg = HmacDRBG::<Sha256>::new(&entropy_bytes, &[], &[]);
    unsafe {
        drbg.generate_to_slice(slice_assume_init_mut(dest), None);
    }

    Ok(())
}
