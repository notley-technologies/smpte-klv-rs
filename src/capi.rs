//! C interface declared in include/smpte_klv.h.
#![allow(unsafe_code)]

use crate::{
    encode, BerForm, Config, DecodeOptions, Decoder, DefinedLengthPackEncoder, Frame, GlobalSetEncoder, Group,
    GroupKind, IndefiniteLength, LocalSetEncoder, SliceSink, Triplet, UniversalLabel, UniversalSetEncoder,
    VariableLengthPackEncoder,
};
use std::ffi::{c_char, c_void};
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::{ptr, slice};

const OK: i32 = 0;
const EMPTY: i32 = 1;
const INCOMPLETE: i32 = 2;
const STOPPED: i32 = 3;
const NULL: i32 = -1;
const INVALID: i32 = -2;
const MALFORMED: i32 = -3;
const BUFFER: i32 = -4;
const PANIC: i32 = -5;
const POISONED: i32 = -6;

type Status = Result<i32, i32>;

fn guarded(f: impl FnOnce() -> Status) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(PANIC)).unwrap_or_else(|e| e)
}

struct Handle<T> {
    state: T,
    poisoned: bool,
}

impl<T> Handle<T> {
    unsafe fn new(out: *mut *mut Self, init: impl FnOnce() -> Result<T, i32>) -> i32 {
        guarded(|| {
            if out.is_null() {
                return Err(NULL);
            }
            out.write(ptr::null_mut());
            out.write(Box::into_raw(Box::new(Handle { state: init()?, poisoned: false })));
            Ok(OK)
        })
    }

    unsafe fn call(handle: *mut Self, f: impl FnOnce(&mut T) -> Status) -> i32 {
        let Some(handle) = handle.as_mut() else { return NULL };
        if handle.poisoned {
            return POISONED;
        }
        let status = guarded(|| f(&mut handle.state));
        if status == PANIC {
            handle.poisoned = true;
        }
        status
    }

    unsafe fn free(handle: *mut Self) {
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    }
}

unsafe fn bytes<'a>(data: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        Ok(&[])
    } else if data.is_null() {
        Err(NULL)
    } else if len > isize::MAX as usize {
        Err(INVALID)
    } else {
        Ok(slice::from_raw_parts(data, len))
    }
}

unsafe fn label(key: *const [u8; 16]) -> Result<UniversalLabel, i32> {
    key.as_ref().copied().map(UniversalLabel::from_bytes).ok_or(NULL)
}

// Only the leading uint32_t is known to exist until we have read it.
// Never create a reference to the full record in caller memory.
unsafe fn record_size<T>(record: *const T) -> Result<usize, i32> {
    if record.is_null() {
        return Err(NULL);
    }
    let size = record.cast::<u32>().read() as usize;
    if size < size_of::<u32>() {
        return Err(INVALID);
    }
    Ok(size.min(size_of::<T>()))
}

// All records passed here are repr(C), begin with struct_size, and contain
// only C scalars or pointers. The caller may have an older or newer header.
unsafe fn write_record<T>(out: *mut T, value: T, size: usize) {
    ptr::copy_nonoverlapping(ptr::addr_of!(value).cast::<u8>(), out.cast(), size);
    out.cast::<u32>().write(size as u32);
}

const LENIENT: u32 = 1;
const ALLOW_NON_SMPTE: u32 = 2;
const INDEFINITE_TO_END: u32 = 4;
const SKIP_FILL: u32 = 8;

fn options(flags: u32) -> Result<DecodeOptions, i32> {
    if flags & !(LENIENT | ALLOW_NON_SMPTE | INDEFINITE_TO_END | SKIP_FILL) != 0 {
        return Err(INVALID);
    }
    let mut opts = if flags & LENIENT == 0 { DecodeOptions::strict() } else { DecodeOptions::lenient() };
    opts.require_smpte_key = flags & ALLOW_NON_SMPTE == 0;
    if flags & INDEFINITE_TO_END != 0 {
        opts.indefinite_length = IndefiniteLength::ToEnd;
    }
    opts.skip_fill = flags & SKIP_FILL != 0;
    Ok(opts)
}

fn group_code(key: UniversalLabel) -> u32 {
    match key.group_coding().map(|coding| coding.kind()) {
        None => 0,
        Some(GroupKind::UniversalSet) => 1,
        Some(GroupKind::GlobalSet) => 2,
        Some(GroupKind::LocalSet) => 3,
        Some(GroupKind::VariableLengthPack) => 4,
        Some(GroupKind::DefinedLengthPack) => 5,
    }
}

#[no_mangle]
extern "C" fn smpte_klv_abi_version() -> u32 {
    1
}

#[no_mangle]
extern "C" fn smpte_klv_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[no_mangle]
extern "C" fn smpte_klv_status_string(status: i32) -> *const c_char {
    let text = match status {
        OK => "ok\0",
        EMPTY => "no frame available\0",
        INCOMPLETE => "more input required\0",
        STOPPED => "visitor stopped\0",
        NULL => "null pointer\0",
        INVALID => "invalid argument\0",
        MALFORMED => "malformed KLV\0",
        BUFFER => "output buffer too small\0",
        PANIC => "internal error\0",
        POISONED => "handle unusable after an internal error\0",
        _ => "unknown status\0",
    };
    text.as_ptr().cast()
}

#[repr(C)]
struct TripletView {
    struct_size: u32,
    group: u32,
    offset: u64,
    key: [u8; 16],
    raw: *const u8,
    raw_len: usize,
    value: *const u8,
    value_len: usize,
}

impl TripletView {
    fn new(triplet: Triplet<'_>, offset: u64) -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            group: group_code(triplet.key()),
            offset,
            key: *triplet.key().as_bytes(),
            raw: triplet.as_bytes().as_ptr(),
            raw_len: triplet.encoded_len(),
            value: triplet.value().as_ptr(),
            value_len: triplet.value().len(),
        }
    }
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_parse(
    data: *const u8,
    len: usize,
    flags: u32,
    out: *mut TripletView,
    needed: *mut usize,
) -> i32 {
    guarded(|| {
        let size = record_size(out)?;
        let result = Triplet::parse_with(bytes(data, len)?, &options(flags)?);
        if !needed.is_null() {
            needed.write(result.as_ref().err().and_then(|e| e.needed()).unwrap_or(0));
        }
        let triplet = result.map_err(|e| if e.is_incomplete() { INCOMPLETE } else { MALFORMED })?;
        write_record(out, TripletView::new(triplet, 0), size);
        Ok(OK)
    })
}

#[repr(C)]
struct ItemView {
    struct_size: u32,
    group: u32,
    tag: u64,
    key: [u8; 16],
    value: *const u8,
    value_len: usize,
}

type Visitor = unsafe extern "C" fn(*const ItemView, *mut c_void) -> i32;

#[no_mangle]
unsafe extern "C" fn smpte_klv_visit_group(
    key: *const [u8; 16],
    value: *const u8,
    len: usize,
    flags: u32,
    visit: Option<Visitor>,
    context: *mut c_void,
) -> i32 {
    guarded(|| {
        let visit = visit.ok_or(NULL)?;
        let key = label(key)?;
        let group = Group::new(key, bytes(value, len)?, options(flags)?).ok_or(INVALID)?;
        let kind = group_code(key);
        let item = |key: [u8; 16], tag: u64, value: &[u8]| {
            let view = ItemView {
                struct_size: size_of::<ItemView>() as u32,
                group: kind,
                tag,
                key,
                value: value.as_ptr(),
                value_len: value.len(),
            };
            if visit(&view, context) == 0 {
                Ok(())
            } else {
                Err(STOPPED)
            }
        };
        match group {
            Group::Universal(set) => {
                for t in set.iter() {
                    let t = t.map_err(|_| MALFORMED)?;
                    item(*t.key().as_bytes(), 0, t.value())?;
                }
            }
            Group::Global(set) => {
                for i in set.iter() {
                    let i = i.map_err(|_| MALFORMED)?;
                    item(*i.key.as_bytes(), 0, i.value)?;
                }
            }
            Group::Local(set) => {
                for i in set.iter() {
                    let i = i.map_err(|_| MALFORMED)?;
                    item([0; 16], i.tag, i.value)?;
                }
            }
            Group::VariableLengthPack(pack) => {
                for i in pack.iter() {
                    let i = i.map_err(|_| MALFORMED)?;
                    item([0; 16], i.index as u64, i.value)?;
                }
            }
            Group::DefinedLengthPack(pack) => item([0; 16], 0, pack.value())?,
        }
        Ok(OK)
    })
}

unsafe fn write_triplet(
    key: UniversalLabel,
    value: &[u8],
    dest: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> Status {
    if written.is_null() || (dest.is_null() && capacity != 0) {
        return Err(NULL);
    }
    let required = encode::triplet_size(value.len(), BerForm::Minimal).map_err(|_| INVALID)?;
    written.write(required);
    if capacity < required {
        return Err(BUFFER);
    }
    // A C output buffer may be uninitialized. Encode the header locally so
    // we can write the entire packet without forming a slice over that buffer.
    let mut header = [0; 16 + 9];
    let header_len = encode::write_header(key, value.len() as u64, BerForm::Minimal, &mut SliceSink::new(&mut header))
        .map_err(|_| INVALID)?;
    ptr::copy_nonoverlapping(header.as_ptr(), dest, header_len);
    ptr::copy_nonoverlapping(value.as_ptr(), dest.add(header_len), value.len());
    Ok(OK)
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_encode_triplet(
    key: *const [u8; 16],
    value: *const u8,
    len: usize,
    dest: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    guarded(|| write_triplet(label(key)?, bytes(value, len)?, dest, capacity, written))
}

enum Encoder {
    Universal(UniversalSetEncoder),
    Global(GlobalSetEncoder),
    Local(LocalSetEncoder),
    Variable(VariableLengthPackEncoder),
    Defined(DefinedLengthPackEncoder),
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_encoder_new(key: *const [u8; 16], out: *mut *mut Handle<Encoder>) -> i32 {
    Handle::new(out, || {
        let key = label(key)?;
        match key.group_coding().map(|coding| coding.kind()).ok_or(INVALID)? {
            GroupKind::UniversalSet => UniversalSetEncoder::new(key).map(Encoder::Universal),
            GroupKind::GlobalSet => GlobalSetEncoder::new(key).map(Encoder::Global),
            GroupKind::LocalSet => LocalSetEncoder::new(key).map(Encoder::Local),
            GroupKind::VariableLengthPack => VariableLengthPackEncoder::new(key).map(Encoder::Variable),
            GroupKind::DefinedLengthPack => DefinedLengthPackEncoder::new(key).map(Encoder::Defined),
        }
        .map_err(|_| INVALID)
    })
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_encoder_add(
    encoder: *mut Handle<Encoder>,
    item_key: *const [u8; 16],
    tag: u64,
    value: *const u8,
    len: usize,
) -> i32 {
    Handle::call(encoder, |encoder| {
        let value = bytes(value, len)?;
        match encoder {
            Encoder::Universal(e) => {
                e.item(label(item_key)?, value).map_err(|_| INVALID)?;
            }
            Encoder::Global(e) => {
                e.item(label(item_key)?, value).map_err(|_| INVALID)?;
            }
            Encoder::Local(e) => {
                e.item(tag, value).map_err(|_| INVALID)?;
            }
            Encoder::Variable(e) => {
                e.item(value).map_err(|_| INVALID)?;
            }
            Encoder::Defined(e) => {
                e.item(value);
            }
        }
        Ok(OK)
    })
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_encoder_write(
    encoder: *mut Handle<Encoder>,
    dest: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    Handle::call(encoder, |encoder| {
        let (key, value) = match encoder {
            Encoder::Universal(e) => (e.key(), e.value()),
            Encoder::Global(e) => (e.key(), e.value()),
            Encoder::Local(e) => (e.key(), e.value()),
            Encoder::Variable(e) => (e.key(), e.value()),
            Encoder::Defined(e) => (e.key(), e.value()),
        };
        write_triplet(key, value, dest, capacity, written)
    })
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_encoder_free(encoder: *mut Handle<Encoder>) {
    Handle::free(encoder);
}

#[repr(C)]
struct DecoderConfig {
    struct_size: u32,
    flags: u32,
    max_value_len: u64,
    max_queue_bytes: u64,
    max_skip_len: u64,
    resync_on_reserved_category: u32,
    reserved: u32,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        let config = Config::default();
        Self {
            struct_size: size_of::<Self>() as u32,
            flags: 0,
            max_value_len: config.max_value_len as u64,
            max_queue_bytes: config.max_queue_bytes as u64,
            max_skip_len: config.max_skip_len,
            resync_on_reserved_category: 0,
            reserved: 0,
        }
    }
}

impl DecoderConfig {
    unsafe fn read(record: *const Self) -> Result<Config, i32> {
        let mut config = Config::default();
        if record.is_null() {
            return Ok(config);
        }
        let size = record_size(record)?;
        let mut input = Self::default();
        // Read complete fields only. Old callers may have supplied just a prefix.
        let end = [4, 8, 16, 24, 32, 36, 40].into_iter().rev().find(|end| *end <= size).unwrap_or(4);
        ptr::copy_nonoverlapping(record.cast::<u8>(), ptr::addr_of_mut!(input).cast(), end);
        if input.flags & INDEFINITE_TO_END != 0 || input.resync_on_reserved_category > 1 || input.reserved != 0 {
            return Err(INVALID);
        }
        config.options = options(input.flags)?;
        config.max_value_len = usize::try_from(input.max_value_len).map_err(|_| INVALID)?;
        config.max_queue_bytes = usize::try_from(input.max_queue_bytes).map_err(|_| INVALID)?;
        config.max_skip_len = input.max_skip_len;
        config.resync_on_reserved_category = input.resync_on_reserved_category != 0;
        Ok(config)
    }
}

struct Stream {
    decoder: Decoder,
    current: Option<Frame>,
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_config_default(config: *mut DecoderConfig) -> i32 {
    guarded(|| {
        let size = record_size(config)?;
        write_record(config, DecoderConfig::default(), size);
        Ok(OK)
    })
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_decoder_new(config: *const DecoderConfig, out: *mut *mut Handle<Stream>) -> i32 {
    Handle::new(out, || Ok(Stream { decoder: Decoder::with_config(DecoderConfig::read(config)?), current: None }))
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_decoder_filter(decoder: *mut Handle<Stream>, key: *const [u8; 16]) -> i32 {
    Handle::call(decoder, |stream| {
        if key.is_null() {
            stream.decoder.clear_filter();
        } else {
            let key = label(key)?;
            stream.decoder.set_filter(move |header| header.key() == key);
        }
        Ok(OK)
    })
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_decoder_push(decoder: *mut Handle<Stream>, data: *const u8, len: usize) -> i32 {
    Handle::call(decoder, |stream| {
        stream.decoder.push(bytes(data, len)?);
        Ok(OK)
    })
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_decoder_finish(decoder: *mut Handle<Stream>) -> i32 {
    Handle::call(decoder, |stream| {
        stream.decoder.finish();
        Ok(OK)
    })
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_decoder_next(decoder: *mut Handle<Stream>, out: *mut TripletView) -> i32 {
    Handle::call(decoder, |stream| {
        let size = record_size(out)?;
        let frame = stream.decoder.next_frame().ok_or(EMPTY)?;
        let current = stream.current.insert(frame);
        write_record(out, TripletView::new(current.triplet(), current.offset()), size);
        Ok(OK)
    })
}

#[repr(C)]
struct DecoderStats {
    struct_size: u32,
    reserved: u32,
    bytes: u64,
    frames: u64,
    frame_bytes: u64,
    bytes_skipped: u64,
    resyncs: u64,
    malformed: u64,
    oversized: u64,
    fill_skipped: u64,
    filtered: u64,
    dropped: u64,
    truncated_at_finish: u64,
    buffered: u64,
    queued: u64,
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_decoder_stats(decoder: *mut Handle<Stream>, out: *mut DecoderStats) -> i32 {
    Handle::call(decoder, |stream| {
        let size = record_size(out)?;
        let s = stream.decoder.stats();
        let stats = DecoderStats {
            struct_size: size_of::<DecoderStats>() as u32,
            reserved: 0,
            bytes: s.bytes,
            frames: s.frames,
            frame_bytes: s.frame_bytes,
            bytes_skipped: s.bytes_skipped,
            resyncs: s.resyncs,
            malformed: s.malformed,
            oversized: s.oversized,
            fill_skipped: s.fill_skipped,
            filtered: s.filtered,
            dropped: s.dropped,
            truncated_at_finish: s.truncated_at_finish,
            buffered: stream.decoder.buffered() as u64,
            queued: stream.decoder.queued() as u64,
        };
        write_record(out, stats, size);
        Ok(OK)
    })
}

#[no_mangle]
unsafe extern "C" fn smpte_klv_decoder_free(decoder: *mut Handle<Stream>) {
    Handle::free(decoder);
}
