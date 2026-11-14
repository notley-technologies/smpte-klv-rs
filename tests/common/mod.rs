//! Helpers shared by the integration tests and the fuzz harnesses.
#![allow(dead_code)]

use smpte_klv::{BerForm, LengthEncoding, UniversalLabel};

/// Small deterministic generator (xorshift64*), so tests need no
/// dependencies and every run is reproducible.
#[derive(Clone, Debug)]
pub struct Rng(pub u64);

impl Rng {
    /// A generator for `seed`, distinct for each `salt`, never in the
    /// all-zero state xorshift cannot leave.
    pub fn seeded(seed: u64, salt: &str) -> Rng {
        // FNV-1a of the salt, then a splitmix64 finaliser.
        let mut z = salt.bytes().fold(0xCBF2_9CE4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01B3));
        z ^= seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Rng(if z == 0 { 1 } else { z })
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `0..n`; 0 when `n` is 0.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

pub fn ul(s: &str) -> UniversalLabel {
    s.parse().unwrap()
}

/// A key followed by a BER length and the value.
pub fn klv(key: UniversalLabel, value: &[u8]) -> Vec<u8> {
    klv_with(key, value, BerForm::Minimal)
}

pub fn klv_with(key: UniversalLabel, value: &[u8], form: BerForm) -> Vec<u8> {
    let mut out = Vec::new();
    smpte_klv::encode::write_triplet(key, value, form, &mut out).unwrap();
    out
}

/// A length field in `enc`.
pub fn len_field(enc: LengthEncoding, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    enc.encode(n as u64, BerForm::Minimal, &mut out).unwrap();
    out
}

/// The examples in SMPTE ST 336:2017 Annexes A to H, and the Global Set
/// example of ST 336M-2007 Annex F, byte for byte.
pub mod annex {
    use super::*;

    pub const MAIN_TITLE: &[u8] = b"Yesterdays World";
    pub const VERSION_TITLE: &[u8] = b"International Edition";
    pub const SOURCE_ORG: &[u8] = b"WXYZ15";

    pub fn main_title_key() -> UniversalLabel {
        ul("06 0E 2B 34 01 01 01 01 01 05 02 00 00 00 00 00")
    }
    pub fn version_title_key() -> UniversalLabel {
        ul("06 0E 2B 34 01 01 01 02 01 05 08 00 00 00 00 00")
    }
    pub fn source_org_key() -> UniversalLabel {
        ul("06 0E 2B 34 01 01 01 01 02 01 01 00 00 00 00 00")
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// Annex B: one metadata item.
    pub fn single_item() -> Vec<u8> {
        cat(&[main_title_key().as_bytes(), &[0x10], MAIN_TITLE])
    }

    pub fn universal_set_key() -> UniversalLabel {
        ul("06 0E 2B 34 02 01 01 01 0F 01 01 01 00 00 00 00")
    }

    /// Annex C.
    pub fn universal_set() -> Vec<u8> {
        cat(&[
            universal_set_key().as_bytes(),
            &[0x5E],
            main_title_key().as_bytes(),
            &[0x10],
            MAIN_TITLE,
            version_title_key().as_bytes(),
            &[0x15],
            VERSION_TITLE,
            source_org_key().as_bytes(),
            &[0x06],
            SOURCE_ORG,
        ])
    }

    pub fn global_set_key() -> UniversalLabel {
        ul("06 0E 2B 34 02 02 08 01 06 0E 2B 34 01 01 01 00")
    }

    /// Annex D.
    pub fn global_set() -> Vec<u8> {
        cat(&[
            global_set_key().as_bytes(),
            &[0x3D],
            &[0x01, 0x01, 0x05, 0x02, 0x00, 0x10],
            MAIN_TITLE,
            &[0x02, 0x01, 0x05, 0x08, 0x00, 0x15],
            VERSION_TITLE,
            &[0x01, 0x02, 0x01, 0x01, 0x00, 0x06],
            SOURCE_ORG,
        ])
    }

    pub fn isan_key() -> UniversalLabel {
        ul("06 0E 2B 34 01 01 01 01 01 01 11 00 00 00 00 00")
    }
    pub const ISAN: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];

    pub fn global_set_2007_key() -> UniversalLabel {
        ul("06 0E 2B 34 02 02 01 01 06 0E 2B 34 01 01 01 01")
    }

    /// ST 336M-2007 Annex F: an 8-byte designator, so no terminator.
    pub fn global_set_2007() -> Vec<u8> {
        cat(&[
            global_set_2007_key().as_bytes(),
            &[0x35],
            &[0x01, 0x05, 0x02, 0x00, 0x10],
            MAIN_TITLE,
            &[0x01, 0x01, 0x11, 0x00, 0x10],
            &ISAN,
            &[0x02, 0x01, 0x01, 0x00, 0x06],
            SOURCE_ORG,
        ])
    }

    pub fn local_set_key() -> UniversalLabel {
        ul("06 0E 2B 34 02 03 01 01 0F 01 01 01 00 00 00 00")
    }

    /// Annex E.
    pub fn local_set() -> Vec<u8> {
        cat(&[
            local_set_key().as_bytes(),
            &[0x31],
            &[0x01, 0x10],
            MAIN_TITLE,
            &[0x02, 0x15],
            VERSION_TITLE,
            &[0x03, 0x06],
            SOURCE_ORG,
        ])
    }

    pub fn vl_pack_key() -> UniversalLabel {
        ul("06 0E 2B 34 02 04 01 01 0F 01 01 01 00 00 00 00")
    }

    /// Annex F.
    pub fn variable_length_pack() -> Vec<u8> {
        cat(&[vl_pack_key().as_bytes(), &[0x2E, 0x10], MAIN_TITLE, &[0x15], VERSION_TITLE, &[0x06], SOURCE_ORG])
    }

    pub fn dl_pack_key() -> UniversalLabel {
        ul("06 0E 2B 34 02 05 01 01 0F 01 01 02 00 00 00 00")
    }

    /// Annex G: Copy Count (UInt8) 3, then the Main Title.
    pub fn defined_length_pack() -> Vec<u8> {
        cat(&[dl_pack_key().as_bytes(), &[0x11, 0x03], MAIN_TITLE])
    }

    /// Annex H.
    pub fn label() -> UniversalLabel {
        ul("06 0E 2B 34 04 01 01 01 04 01 01 01 01 01 00 00")
    }

    /// Annex A.
    pub fn isan_metadata_key() -> UniversalLabel {
        ul("06 0E 2B 34 01 01 01 01 01 01 11 01 00 00 00 00")
    }
}
