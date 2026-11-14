//! Push-based decoding of KLV streams.

use crate::error::MAX_LEN;
use crate::group::Group;
use crate::triplet::KEY_LEN;
use crate::{Category, DecodeOptions, Header, Triplet, UniversalLabel};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

/// Limits and options for a [`Decoder`].
///
/// ```
/// let mut config = smpte_klv::Config::default();
/// config.max_value_len = 64 * 1024;   // skip anything bigger without buffering it
/// config.options.skip_fill = true;    // drop KLV Fill items
/// let decoder = smpte_klv::Decoder::with_config(config);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct Config {
    /// Largest value accepted, in bytes. A triplet with a longer value is
    /// skipped by its declared length without being buffered, and counted in
    /// [`Stats::oversized`], unless it is longer than
    /// [`max_skip_len`](Self::max_skip_len). Default 16 MiB.
    pub max_value_len: usize,
    /// Most memory, in bytes, held by complete frames waiting for
    /// [`Decoder::next_frame`]: each frame counts its bytes plus
    /// [`FRAME_OVERHEAD`] for its bookkeeping. A frame that would go over is
    /// dropped and counted in [`Stats::dropped`]; one frame is always
    /// accepted into an empty queue. Default 64 MiB.
    pub max_queue_bytes: usize,
    /// Largest triplet, in bytes (key, length field and value), that the
    /// decoder skips by its declared length when it does not keep it: a
    /// Fill item, one the filter rejects, or one over
    /// [`max_value_len`](Self::max_value_len). A longer one is treated as
    /// damage instead: counted in [`Stats::malformed`], and the decoder
    /// resynchronises on the next key after its first byte.
    ///
    /// Skipping by the declared length is what ST 336 implies, and the
    /// default ([`u64::MAX`]) always does it. But one bit error in a
    /// long-form length can declare gigabytes, and skipping that many bytes
    /// discards everything after it. A stream known to carry only small
    /// triplets recovers from such damage with this set to a little more
    /// than its largest triplet; the cost is that a genuine triplet longer
    /// than this is scanned through, where a false key inside its value could
    /// be found.
    ///
    /// The bound does not apply to a triplet the decoder keeps: a damaged
    /// length on a wanted key that still fits
    /// [`max_value_len`](Self::max_value_len) is buffered as declared, and
    /// the frame carries the bytes that follow. So the most one damaged
    /// length can cost is the larger of the two limits; keep both close to
    /// the largest triplet the stream really carries.
    pub max_skip_len: u64,
    /// Decoding options. [`DecodeOptions::require_smpte_key`] (on by
    /// default) makes the decoder skip anything that does not start with the
    /// SMPTE prefix and resynchronise on the next one. Without it there is no
    /// resynchronisation: any 16 bytes are a key, framing relies on every
    /// length being right, and damage misaligns everything after it until a
    /// reserved, indefinite or overflowing length turns up by chance.
    /// [`DecodeOptions::skip_fill`] drops Fill items, and
    /// [`DecodeOptions::reject_label_keys`] makes a SMPTE Label where a key
    /// should be count as damage. A `0x80` length is always treated as
    /// damage: a stream has no buffer end for
    /// [`IndefiniteLength::ToEnd`](crate::IndefiniteLength::ToEnd) to use.
    /// The options also apply to [`Frame::triplet`] and [`Frame::group`].
    pub options: DecodeOptions,
    /// Treat a candidate key whose byte 5 is a reserved category (anything
    /// but `01` to `05`, SMPTE ST 336:2017 Table 3) as damage and keep
    /// scanning, instead of skipping the triplet by its declared length.
    ///
    /// ST 336:2017 section 5.2.1 asks decoders to pass unknown values on, so
    /// this is off by default. In damaged data the prefix turns up by
    /// chance, and jumping a length read from such a false key can swallow
    /// the real triplets after it; a stream known to carry only registered
    /// keys resynchronises better with this on. Default false.
    pub resync_on_reserved_category: bool,
}

/// Bytes each queued [`Frame`] counts against [`Config::max_queue_bytes`]
/// beyond its own bytes: the frame record and its share of the queue and of
/// the allocator's rounding.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub const FRAME_OVERHEAD: usize = core::mem::size_of::<Frame>() + 16;

impl Default for Config {
    fn default() -> Self {
        Config {
            max_value_len: 16 << 20,
            max_queue_bytes: 64 << 20,
            max_skip_len: u64::MAX,
            options: DecodeOptions::default(),
            resync_on_reserved_category: false,
        }
    }
}

/// Counters kept by a [`Decoder`]. Byte counts are of input bytes, and every
/// pushed byte ends up in exactly one of [`frame_bytes`](Self::frame_bytes),
/// [`bytes_skipped`](Self::bytes_skipped) or
/// [`Decoder::buffered`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct Stats {
    /// Bytes pushed.
    pub bytes: u64,
    /// Complete frames queued.
    pub frames: u64,
    /// Bytes of the frames queued.
    pub frame_bytes: u64,
    /// Bytes not delivered in any frame: damage, skipped and dropped
    /// triplets, and incomplete bytes at [`Decoder::finish`].
    pub bytes_skipped: u64,
    /// Runs of damaged bytes skipped to find the next key.
    pub resyncs: u64,
    /// Candidate keys the decoder resynchronised after instead of trusting:
    /// those followed by a reserved, indefinite or impossibly large length,
    /// rejected by the [options](Config::options) (a Label, say), with a
    /// reserved category under [`Config::resync_on_reserved_category`], or
    /// declaring a skip longer than [`Config::max_skip_len`].
    pub malformed: u64,
    /// Triplets the filter kept but skipped because their value is longer
    /// than [`Config::max_value_len`] (those longer than
    /// [`Config::max_skip_len`] are [`malformed`](Self::malformed)).
    pub oversized: u64,
    /// Fill items skipped ([`DecodeOptions::skip_fill`]).
    pub fill_skipped: u64,
    /// Triplets skipped by the [`Decoder::set_filter`] filter (those longer
    /// than [`Config::max_skip_len`] are [`malformed`](Self::malformed)).
    pub filtered: u64,
    /// Complete frames dropped because the queue was full.
    pub dropped: u64,
    /// Incomplete triplets cut off by [`Decoder::finish`].
    pub truncated_at_finish: u64,
}

/// A complete triplet delivered by a [`Decoder`], owning its bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct Frame {
    bytes: Vec<u8>,
    header_len: usize,
    offset: u64,
    opts: DecodeOptions,
}

impl Frame {
    /// The key.
    pub fn key(&self) -> UniversalLabel {
        UniversalLabel::from_slice(&self.bytes).expect("a frame holds a whole key")
    }

    /// The value bytes.
    pub fn value(&self) -> &[u8] {
        &self.bytes[self.header_len..]
    }

    /// The whole triplet as received.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Bytes taken by the key and length field.
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Bytes taken by the whole triplet.
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// Position of the frame's first byte in the stream: bytes pushed before
    /// it since the decoder was created or [reset](Decoder::reset).
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// A borrowed view of the triplet.
    pub fn triplet(&self) -> Triplet<'_> {
        Triplet::from_valid(&self.bytes, self.header_len, self.opts)
    }

    /// The value as a set or pack, if the key declares one.
    pub fn group(&self) -> Option<Group<'_>> {
        self.triplet().group()
    }

    /// The bytes, without copying.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("key", &self.key())
            .field("value_len", &self.value().len())
            .field("offset", &self.offset)
            .finish()
    }
}

/// Decides whether to keep a triplet, given its header; see
/// [`Decoder::set_filter`].
type Filter = Box<dyn FnMut(&Header) -> bool + Send>;

/// What becomes of a triplet whose header has been read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    Keep,
    Fill,
    Filtered,
    Oversized,
}

enum Step {
    /// This many bytes from the front of the input are dealt with.
    Consumed(usize),
    /// Progress needs the input to hold this many bytes.
    NeedMore(usize),
}

/// Decoder for a stream of KLV triplets, such as a `.klv` file or the payload
/// of an asynchronous KLV elementary stream (SMPTE RP 217, MISB ST 1402).
///
/// Push bytes in chunks of any size as they arrive and collect complete
/// triplets as [`Frame`]s. The frames and the order they come in do not
/// depend on how the input is split into pushes, and neither do the
/// [`Stats`] once [`finish`](Self::finish) has been called (before that, a
/// few bytes may still be waiting to be scanned) as long as the queue limit
/// has not dropped anything.
///
/// Memory is bounded by [`Config`]: a value longer than
/// [`max_value_len`](Config::max_value_len) is skipped by its declared length
/// without being buffered, and at most
/// [`max_queue_bytes`](Config::max_queue_bytes) of complete frames wait to be
/// collected. A triplet the [filter](Self::set_filter) rejects is skipped the
/// same way, so a decoder interested in one key never buffers the others.
/// Fill items are dropped first (with [`DecodeOptions::skip_fill`]), then the
/// filter runs, then the size limit applies.
///
/// With [`DecodeOptions::require_smpte_key`] (the default), damaged input is
/// skipped by scanning for the next `06 0E 2B 34` (every SMPTE key starts
/// with it): garbage between triplets, and candidate keys whose length is
/// reserved (`0xFF`), indefinite (`0x80`) or overflows. A damaged length that
/// is still valid cannot be told from a real one; [`Config::max_skip_len`]
/// bounds how much such a length can make the decoder skip. Damage inside a
/// value cannot be detected at this level; that is for the value's own
/// checks, such as a checksum the defining document specifies.
///
/// A `Decoder` is [`Send`] but not [`Sync`]: its filter is a `FnMut`.
///
/// ```
/// use smpte_klv::Decoder;
///
/// let mut packet = vec![0x06, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 1, 5, 2, 0, 0, 0, 0, 0, 3];
/// packet.extend(b"abc");
///
/// let mut decoder = Decoder::new();
/// decoder.push(&[0xDE, 0xAD]);       // garbage is skipped
/// decoder.push(&packet[..10]);       // any split works
/// decoder.push(&packet[10..]);
/// let frame = decoder.next_frame().unwrap();
/// assert_eq!(frame.value(), b"abc");
/// assert_eq!(frame.offset(), 2);
/// assert_eq!(decoder.stats().bytes_skipped, 2);
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct Decoder {
    cfg: Config,
    filter: Option<Filter>,
    /// Input not yet resolved, starting at a candidate key or at bytes still
    /// to scan.
    buf: Vec<u8>,
    /// Bytes `buf` must hold before trying again.
    need: usize,
    /// Bytes of a skipped triplet still to drop from the input.
    skip: u64,
    /// Total size of a triplet whose header was accepted, while its value
    /// is still arriving; the filter has already seen it.
    accepted: Option<usize>,
    /// Inside a run of damaged bytes (one resync is counted per run).
    discarding: bool,
    /// Stream position of the first byte of the input being decoded.
    offset: u64,
    ready: VecDeque<Frame>,
    ready_bytes: usize,
    stats: Stats,
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("config", &self.cfg)
            .field("filter", &self.filter.is_some())
            .field("buffered", &self.buf.len())
            .field("queued", &self.ready.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder with the default [`Config`].
    pub fn new() -> Self {
        Decoder::with_config(Config::default())
    }

    /// A decoder with this configuration.
    pub fn with_config(cfg: Config) -> Self {
        Decoder {
            cfg,
            filter: None,
            buf: Vec::new(),
            need: 0,
            skip: 0,
            accepted: None,
            discarding: false,
            offset: 0,
            ready: VecDeque::new(),
            ready_bytes: 0,
            stats: Stats::default(),
        }
    }

    /// The configuration in use.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Keep only triplets for which `filter` returns true. It is called once
    /// per triplet, with the key and length, before the value is buffered;
    /// rejected triplets are skipped and counted in [`Stats::filtered`], or
    /// treated as damage if longer than [`Config::max_skip_len`].
    ///
    /// ```
    /// use smpte_klv::{Decoder, UniversalLabel};
    ///
    /// let wanted: UniversalLabel = "06.0E.2B.34.02.0B.01.01.0E.01.03.01.01.00.00.00".parse().unwrap();
    /// let mut decoder = Decoder::new();
    /// decoder.set_filter(move |h| h.key().eq_ignoring_version(&wanted));
    /// ```
    pub fn set_filter(&mut self, filter: impl FnMut(&Header) -> bool + Send + 'static) {
        self.filter = Some(Box::new(filter));
    }

    /// Remove the filter.
    pub fn clear_filter(&mut self) {
        self.filter = None;
    }

    /// Feed more input.
    pub fn push(&mut self, mut data: &[u8]) {
        self.stats.bytes += data.len() as u64;
        while !data.is_empty() {
            if self.skip > 0 {
                let n = usize::try_from(self.skip).unwrap_or(usize::MAX).min(data.len());
                self.drop_skipped(n);
                data = &data[n..];
                continue;
            }
            if self.buf.is_empty() {
                // Decode straight from the caller's bytes; only an
                // incomplete tail is copied.
                match self.step(data) {
                    Step::Consumed(n) => {
                        self.offset += n as u64;
                        data = &data[n..];
                    }
                    Step::NeedMore(n) => {
                        self.buf.extend_from_slice(data);
                        self.need = n;
                        data = &[];
                    }
                }
            } else {
                // Take only what the current step needs, so a large push
                // never copies more than one triplet. While only a header is
                // awaited, take a larger window so that a run of damage is
                // scanned in bulk rather than a header's worth at a time.
                let mut want = self.need - self.buf.len();
                if self.accepted.is_none() {
                    want = want.max(SCAN_WINDOW);
                }
                let n = want.min(data.len());
                self.buf.extend_from_slice(&data[..n]);
                data = &data[n..];
                if self.buf.len() >= self.need {
                    self.drain_buffer();
                }
            }
        }
    }

    /// Mark the end of input. An incomplete trailing triplet is dropped and
    /// counted in [`Stats::truncated_at_finish`]. Frames already complete
    /// stay available, and the decoder can be fed again afterwards.
    pub fn finish(&mut self) {
        // A chunked push can leave bytes in the buffer that a single push
        // would already have scanned past; scan them the same way first.
        if !self.buf.is_empty() {
            self.drain_buffer();
        }
        if !self.buf.is_empty() {
            let candidate = self.accepted.is_some()
                || !self.cfg.options.require_smpte_key
                || self.buf.starts_with(&UniversalLabel::PREFIX);
            if candidate {
                self.stats.truncated_at_finish += 1;
            }
            self.stats.bytes_skipped += self.buf.len() as u64;
            self.offset += self.buf.len() as u64;
            self.buf.clear();
            if self.buf.capacity() > 64 * 1024 {
                self.buf.shrink_to(SCAN_WINDOW);
            }
        }
        self.skip = 0;
        self.need = 0;
        self.accepted = None;
        self.discarding = false;
    }

    /// The oldest complete frame.
    pub fn next_frame(&mut self) -> Option<Frame> {
        let frame = self.ready.pop_front()?;
        self.ready_bytes -= frame.bytes.len() + FRAME_OVERHEAD;
        if self.ready.is_empty() && self.ready.capacity() > 64 {
            // Give back the slots a burst grew the queue to.
            self.ready.shrink_to(16);
        }
        Some(frame)
    }

    /// Drain every complete frame.
    pub fn frames(&mut self) -> impl Iterator<Item = Frame> + '_ {
        core::iter::from_fn(move || self.next_frame())
    }

    /// Frames waiting to be collected.
    pub fn queued(&self) -> usize {
        self.ready.len()
    }

    /// Input bytes held while waiting for the rest of a triplet.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Bytes of a skipped triplet (Fill, filtered or oversized) still to be
    /// dropped from the input before decoding resumes. Large values show the
    /// decoder is skipping a long declared length, which a caller that knows
    /// better can abandon with [`finish`](Self::finish).
    pub fn skip_remaining(&self) -> u64 {
        self.skip
    }

    /// Counters since creation or the last [`reset`](Self::reset).
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Forget all buffered input, queued frames and counters, keeping the
    /// configuration and filter.
    pub fn reset(&mut self) {
        let filter = self.filter.take();
        *self = Decoder::with_config(self.cfg.clone());
        self.filter = filter;
    }

    fn drop_skipped(&mut self, n: usize) {
        self.skip -= n as u64;
        self.stats.bytes_skipped += n as u64;
        self.offset += n as u64;
    }

    /// Decode as much of `buf` as possible, keeping what is left.
    fn drain_buffer(&mut self) {
        let buf = core::mem::take(&mut self.buf);
        let mut pos = 0;
        while pos < buf.len() {
            if self.skip > 0 {
                let n = usize::try_from(self.skip).unwrap_or(usize::MAX).min(buf.len() - pos);
                self.drop_skipped(n);
                pos += n;
                continue;
            }
            match self.step(&buf[pos..]) {
                Step::Consumed(n) => {
                    self.offset += n as u64;
                    pos += n;
                }
                Step::NeedMore(n) => {
                    self.need = n;
                    break;
                }
            }
        }
        let mut buf = buf;
        buf.drain(..pos);
        if buf.is_empty() && buf.capacity() > 64 * 1024 {
            // Give back what a large frame grew the buffer to.
            buf.shrink_to(SCAN_WINDOW);
        }
        self.buf = buf;
    }

    /// Count `n` damaged bytes at the front of the input.
    fn damaged(&mut self, n: usize) -> Step {
        self.stats.bytes_skipped += n as u64;
        if !self.discarding {
            self.discarding = true;
            self.stats.resyncs += 1;
        }
        Step::Consumed(n)
    }

    /// One decision about the front of `input`. Depends only on the bytes,
    /// never on how much of the stream `input` holds beyond what the
    /// decision needs, which keeps the result independent of chunking.
    fn step(&mut self, input: &[u8]) -> Step {
        if let Some(total) = self.accepted {
            if input.len() < total {
                return Step::NeedMore(total);
            }
            self.accepted = None;
            self.emit(&input[..total]);
            return Step::Consumed(total);
        }
        let opts = &self.cfg.options;
        if opts.require_smpte_key {
            let start = candidate(input);
            if start > 0 {
                return self.damaged(start);
            }
        }
        if self.cfg.resync_on_reserved_category && input.len() > 4 && input[..4] == UniversalLabel::PREFIX {
            if let Category::Reserved(_) = Category::from_byte(input[4]) {
                self.stats.malformed += 1;
                return self.damaged(1);
            }
        }
        let header = match Header::parse_with(input, opts) {
            Ok(h) => h,
            Err(e) => match e.needed() {
                Some(n) => return Step::NeedMore(n),
                None => {
                    self.stats.malformed += 1;
                    return self.damaged(1);
                }
            },
        };
        let (value_len, total) = match (header.length().definite(), header.total_len()) {
            (Some(v), Some(t)) => (v, t),
            _ => {
                self.stats.malformed += 1;
                return self.damaged(1);
            }
        };
        // The whole triplet in memory, if it can be buffered at all: within
        // max_value_len and, on 32-bit targets, within the address space.
        let buffered_total = usize::try_from(value_len)
            .ok()
            .filter(|&v| v <= self.cfg.max_value_len)
            .and_then(|v| header.header_len().checked_add(v))
            .filter(|&t| t <= MAX_LEN);
        // The size limit comes last so that `oversized` counts only triplets
        // the caller wanted. The filter is called exactly once per header.
        let fate = if opts.skip_fill && header.key().is_fill() {
            Fate::Fill
        } else if !self.filter.as_mut().map_or(true, |filter| filter(&header)) {
            Fate::Filtered
        } else if buffered_total.is_none() {
            Fate::Oversized
        } else {
            Fate::Keep
        };
        if fate != Fate::Keep && total > self.cfg.max_skip_len {
            self.stats.malformed += 1;
            return self.damaged(1);
        }
        self.discarding = false;
        let total = match (fate, buffered_total) {
            (Fate::Keep, Some(t)) => t,
            _ => {
                match fate {
                    Fate::Fill => self.stats.fill_skipped += 1,
                    Fate::Filtered => self.stats.filtered += 1,
                    _ => self.stats.oversized += 1,
                }
                let n = total.min(input.len() as u64) as usize;
                self.skip = total - n as u64;
                self.stats.bytes_skipped += n as u64;
                return Step::Consumed(n);
            }
        };
        if input.len() < total {
            self.accepted = Some(total);
            return Step::NeedMore(total);
        }
        self.emit(&input[..total]);
        Step::Consumed(total)
    }

    fn emit(&mut self, bytes: &[u8]) {
        let header_len = KEY_LEN + header_len_after_key(&bytes[KEY_LEN..]);
        let cost = bytes.len() + FRAME_OVERHEAD;
        if !self.ready.is_empty() && self.ready_bytes.saturating_add(cost) > self.cfg.max_queue_bytes {
            self.stats.dropped += 1;
            self.stats.bytes_skipped += bytes.len() as u64;
            return;
        }
        self.stats.frames += 1;
        self.stats.frame_bytes += bytes.len() as u64;
        self.ready_bytes += cost;
        self.ready.push_back(Frame { bytes: bytes.to_vec(), header_len, offset: self.offset, opts: self.cfg.options });
    }
}

/// Bytes taken into the buffer at a time while scanning for a header.
const SCAN_WINDOW: usize = 512;

/// Size of a BER length field already known to be valid and definite.
fn header_len_after_key(len: &[u8]) -> usize {
    match len[0] {
        b if b < 0x80 => 1,
        b => 1 + usize::from(b & 0x7F),
    }
}

/// Offset of the first position where a key could start: the full prefix,
/// or the start of it cut off by the end of the input.
fn candidate(input: &[u8]) -> usize {
    let prefix = &UniversalLabel::PREFIX;
    let mut i = 0;
    while i < input.len() {
        match input[i..].iter().position(|&b| b == prefix[0]) {
            None => return input.len(),
            Some(p) => i += p,
        }
        let rest = &input[i..];
        // A fixed-size comparison where possible: one instruction, not a call.
        let hit = match rest.get(..4) {
            Some(w) => w == prefix,
            None => rest == &prefix[..rest.len()],
        };
        if hit {
            return i;
        }
        i += 1;
    }
    input.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const KEY: [u8; 16] = [6, 0x0E, 0x2B, 0x34, 1, 1, 1, 1, 1, 5, 2, 0, 0, 0, 0, 0];

    fn klv(value: &[u8]) -> Vec<u8> {
        let mut v = KEY.to_vec();
        crate::ber::encode_length(value.len() as u64, crate::BerForm::Minimal, &mut v).unwrap();
        v.extend_from_slice(value);
        v
    }

    fn values(d: &mut Decoder) -> Vec<Vec<u8>> {
        d.frames().map(|f| f.value().to_vec()).collect()
    }

    fn check_accounting(d: &Decoder) {
        let s = d.stats();
        assert_eq!(s.bytes, s.frame_bytes + s.bytes_skipped + d.buffered() as u64, "{s:?}");
    }

    #[test]
    fn candidate_scan() {
        assert_eq!(candidate(&[]), 0);
        assert_eq!(candidate(&[1, 2, 3]), 3);
        assert_eq!(candidate(&[1, 6, 0x0E, 0x2B, 0x34, 9]), 1);
        assert_eq!(candidate(&[1, 6, 0x0E]), 1);
        assert_eq!(candidate(&[6, 0x0E, 0x2C, 6]), 3);
        assert_eq!(candidate(&[6, 6, 0x0E, 0x2B, 0x34]), 1);
    }

    #[test]
    fn frames_across_chunks() {
        let mut stream = klv(b"first");
        stream.extend(klv(&[7u8; 300]));
        stream.extend(klv(b""));
        for chunk in [1, 2, 3, 16, 17, 18, 100, stream.len()] {
            let mut d = Decoder::new();
            for c in stream.chunks(chunk) {
                d.push(c);
                check_accounting(&d);
            }
            d.finish();
            let got = values(&mut d);
            assert_eq!(got, vec![b"first".to_vec(), vec![7u8; 300], vec![]], "chunk {chunk}");
            assert_eq!(d.stats().frames, 3);
            assert_eq!(d.stats().bytes_skipped, 0);
            check_accounting(&d);
        }
    }

    #[test]
    fn offsets_and_triplets() {
        let mut stream = vec![0xAA; 3];
        stream.extend(klv(b"x"));
        stream.extend(klv(b"yz"));
        let mut d = Decoder::new();
        d.push(&stream);
        let a = d.next_frame().unwrap();
        let b = d.next_frame().unwrap();
        assert_eq!((a.offset(), b.offset()), (3, 21));
        assert_eq!(b.key(), UniversalLabel::from_bytes(KEY));
        assert_eq!(b.header_len(), 17);
        assert_eq!(b.encoded_len(), 19);
        assert_eq!(b.as_bytes(), &stream[21..]);
        assert_eq!(b.triplet().value(), b"yz");
        assert!(b.group().is_none());
        assert_eq!(b.clone().into_bytes(), stream[21..].to_vec());
        assert!(alloc::format!("{b:?}").contains("value_len: 2"));
        assert_eq!(d.stats().resyncs, 1);
    }

    #[test]
    fn resynchronises_after_damage() {
        let mut stream = vec![6, 0x0E, 0x2B]; // a broken prefix
        stream.extend(klv(b"a"));
        let mut bad = KEY.to_vec();
        bad.push(0xFF); // reserved length
        stream.extend(&bad);
        let mut indefinite = KEY.to_vec();
        indefinite.push(0x80);
        stream.extend(&indefinite);
        stream.extend(klv(b"b"));
        for chunk in [1, 5, stream.len()] {
            let mut d = Decoder::new();
            for c in stream.chunks(chunk) {
                d.push(c);
            }
            assert_eq!(values(&mut d), vec![b"a".to_vec(), b"b".to_vec()], "chunk {chunk}");
            let s = d.stats();
            assert_eq!(s.malformed, 2);
            // The broken prefix, then one run covering both bad keys.
            assert_eq!(s.resyncs, 2);
            assert_eq!(s.bytes_skipped, 3 + 17 + 17);
            check_accounting(&d);
        }
    }

    #[test]
    fn oversized_and_filtered_are_skipped_unbuffered() {
        let mut cfg = Config::default();
        cfg.max_value_len = 4;
        let mut stream = klv(&[1; 1000]);
        stream.extend(klv(b"ok"));
        stream.extend(klv(b"no"));
        let mut d = Decoder::with_config(cfg);
        d.set_filter(|h| h.length() != crate::Length::Definite(2) || h.header_len() == 17);
        let mut max_buffered = 0;
        for c in stream.chunks(7) {
            d.push(c);
            max_buffered = max_buffered.max(d.buffered());
        }
        assert!(max_buffered <= 19, "{max_buffered}");
        assert_eq!(values(&mut d), vec![b"ok".to_vec(), b"no".to_vec()]);
        assert_eq!(d.stats().oversized, 1);

        let mut d = Decoder::new();
        let counter = alloc::sync::Arc::new(core::sync::atomic::AtomicU32::new(0));
        let c2 = counter.clone();
        d.set_filter(move |h| {
            c2.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            h.total_len() != Some(19)
        });
        for c in stream.chunks(1) {
            d.push(c);
        }
        let calls = counter.load(core::sync::atomic::Ordering::Relaxed);
        assert_eq!(calls, 3, "the filter sees each header once");
        assert_eq!(values(&mut d), vec![vec![1u8; 1000]]);
        assert_eq!(d.stats().filtered, 2);
        check_accounting(&d);
        d.clear_filter();
        assert!(!alloc::format!("{d:?}").is_empty());
    }

    #[test]
    fn filter_runs_before_size_limit() {
        let mut cfg = Config::default();
        cfg.max_value_len = 4;
        let mut d = Decoder::with_config(cfg);
        d.set_filter(|h| h.length() == crate::Length::Definite(100));
        let mut stream = klv(&[1; 50]);
        stream.extend(klv(&[2; 100]));
        d.push(&stream);
        assert_eq!(d.stats().filtered, 1);
        assert_eq!(d.stats().oversized, 1);
        assert_eq!(d.queued(), 0);
        check_accounting(&d);
    }

    #[test]
    fn reserved_category_resync_is_opt_in() {
        // A false key with category 0x99 whose length would swallow the
        // real triplet after it.
        let mut stream = KEY.to_vec();
        stream[4] = 0x99;
        stream.push(0x7F);
        stream.extend(klv(b"real"));
        let mut d = Decoder::new();
        d.push(&stream);
        assert!(values(&mut d).is_empty(), "passed on by default, as ST 336 asks");
        let mut cfg = Config::default();
        cfg.resync_on_reserved_category = true;
        let mut d = Decoder::with_config(cfg);
        for c in stream.chunks(3) {
            d.push(c);
        }
        assert_eq!(values(&mut d), vec![b"real".to_vec()]);
        assert_eq!(d.stats().resyncs, 1);
        assert_eq!(d.stats().malformed, 1);
        assert_eq!(d.stats().bytes_skipped, 17);
        check_accounting(&d);
    }

    #[test]
    fn fill_items_can_be_skipped() {
        let mut fill = UniversalLabel::FILL.with_version(1).as_bytes().to_vec();
        fill.extend([3, 0, 0, 0]);
        fill.extend(klv(b"v"));
        let mut cfg = Config::default();
        cfg.options.skip_fill = true;
        let mut d = Decoder::with_config(cfg);
        d.push(&fill);
        assert_eq!(values(&mut d), vec![b"v".to_vec()]);
        assert_eq!(d.stats().fill_skipped, 1);
        let mut d = Decoder::new();
        d.push(&fill);
        assert_eq!(d.frames().count(), 2);
    }

    #[test]
    fn finish_and_reset() {
        let stream = klv(b"abcdef");
        let mut d = Decoder::new();
        d.push(&stream[..20]);
        assert_eq!(d.buffered(), 20);
        d.finish();
        assert_eq!(d.stats().truncated_at_finish, 1);
        assert_eq!(d.buffered(), 0);
        check_accounting(&d);
        // Usable again after finish.
        d.push(&stream);
        assert_eq!(d.next_frame().unwrap().offset(), 20);
        // A partial prefix is just skipped bytes.
        d.push(&[6, 0x0E]);
        d.finish();
        assert_eq!(d.stats().truncated_at_finish, 1);
        d.set_filter(|_| true);
        d.reset();
        assert_eq!(d.stats(), &Stats::default());
        assert!(alloc::format!("{d:?}").contains("filter: true"));
        assert_eq!(d.config(), &Config::default());
    }

    #[test]
    fn finish_scans_what_chunking_left_unscanned() {
        // A broken prefix, then the start of a real key, cut off.
        let tail = [6, 0x0E, 0x2B, 0x35, 6, 0x0E, 0x2B, 0x34, 1];
        let mut whole = Decoder::new();
        whole.push(&tail);
        whole.finish();
        let mut chunked = Decoder::new();
        chunked.push(&tail[..1]);
        chunked.push(&tail[1..]);
        chunked.finish();
        assert_eq!(whole.stats(), chunked.stats());
        assert_eq!(chunked.stats().truncated_at_finish, 1);
        assert_eq!(chunked.stats().resyncs, 1);
    }

    #[test]
    fn queue_limit_drops_newest() {
        let mut cfg = Config::default();
        cfg.max_queue_bytes = 30;
        let mut d = Decoder::with_config(cfg);
        let mut stream = klv(&[1; 5]);
        stream.extend(klv(&[2; 5]));
        d.push(&stream);
        assert_eq!(d.queued(), 1);
        assert_eq!(d.stats().dropped, 1);
        check_accounting(&d);
        assert_eq!(d.next_frame().unwrap().value(), &[1; 5]);
        d.push(&klv(&[3; 5]));
        assert_eq!(d.next_frame().unwrap().value(), &[3; 5]);
    }

    #[test]
    fn queue_limit_counts_frame_overhead() {
        // Room for three 17-byte frames' bytes, but not their bookkeeping.
        let mut cfg = Config::default();
        cfg.max_queue_bytes = 2 * (17 + FRAME_OVERHEAD);
        let mut d = Decoder::with_config(cfg);
        let stream = klv(&[]).repeat(3);
        d.push(&stream);
        assert_eq!(d.queued(), 2);
        assert_eq!(d.stats().dropped, 1);
        assert_eq!(d.frames().count(), 2);
        check_accounting(&d);
        // A burst's queue capacity is given back once drained.
        let mut d = Decoder::new();
        d.push(&klv(&[]).repeat(1000));
        assert_eq!(d.frames().count(), 1000);
        assert!(d.ready.capacity() <= 64, "{}", d.ready.capacity());
    }

    #[test]
    fn long_skips_can_be_bounded() {
        // A damaged length declaring ~4 GiB on a triplet the filter rejects,
        // then real triplets.
        let mut damaged = KEY.to_vec();
        damaged[8] = 9;
        damaged.extend([0x84, 0xF0, 0, 0, 0]);
        let mut stream = damaged.clone();
        stream.extend(klv(b"one"));
        stream.extend(klv(b"two"));
        let wanted = UniversalLabel::from_bytes(KEY);

        let mut d = Decoder::new();
        d.set_filter(move |h| h.key() == wanted);
        d.push(&stream);
        assert!(values(&mut d).is_empty(), "skipped by its declared length by default");
        assert_eq!(d.skip_remaining(), 0xF000_0000 + 21 - stream.len() as u64);
        d.finish();
        assert_eq!(d.skip_remaining(), 0);

        let mut cfg = Config::default();
        cfg.max_skip_len = 1 << 20;
        for chunk in [1, 7, stream.len()] {
            let mut d = Decoder::with_config(cfg.clone());
            d.set_filter(move |h| h.key() == wanted);
            for c in stream.chunks(chunk) {
                d.push(c);
            }
            d.finish();
            assert_eq!(values(&mut d), vec![b"one".to_vec(), b"two".to_vec()], "chunks of {chunk}");
            let s = d.stats();
            assert_eq!((s.malformed, s.resyncs, s.filtered), (1, 1, 0));
            assert_eq!(s.bytes_skipped, damaged.len() as u64);
            check_accounting(&d);
        }
        // Kept triplets are not affected by the bound.
        let mut cfg = Config::default();
        cfg.max_skip_len = 4;
        let mut d = Decoder::with_config(cfg);
        d.push(&klv(b"kept"));
        assert_eq!(values(&mut d), vec![b"kept".to_vec()]);
    }

    #[test]
    fn huge_value_limits_never_overflow() {
        // max_value_len = usize::MAX must not make a huge declared length
        // buffered or overflow the header arithmetic.
        let mut cfg = Config::default();
        cfg.max_value_len = usize::MAX;
        let mut d = Decoder::with_config(cfg);
        let mut stream = KEY.to_vec();
        stream.extend([0x88, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0]);
        d.push(&stream);
        d.push(&[0; 100]);
        assert_eq!(d.stats().oversized, 1);
        assert_eq!(d.buffered(), 0);
        check_accounting(&d);
    }

    #[test]
    fn labels_where_keys_belong_are_damage() {
        // A standalone label (no length or value) before a real triplet.
        let mut label = KEY;
        label[4] = 0x04;
        let mut stream = label.to_vec();
        stream.extend(klv(b"real"));
        let mut d = Decoder::new();
        d.push(&stream);
        assert_eq!(values(&mut d), vec![b"real".to_vec()]);
        assert_eq!((d.stats().malformed, d.stats().resyncs, d.stats().bytes_skipped), (1, 1, 16));
        check_accounting(&d);
    }

    #[test]
    fn without_prefix_requirement() {
        let mut cfg = Config::default();
        cfg.options.require_smpte_key = false;
        let mut other = [9u8; 16].to_vec();
        other.extend([1, 0xAB]);
        let mut d = Decoder::with_config(cfg);
        d.push(&other);
        assert_eq!(d.next_frame().unwrap().value(), &[0xAB]);
        d.push(&other[..5]);
        d.finish();
        assert_eq!(d.stats().truncated_at_finish, 1);
    }
}
