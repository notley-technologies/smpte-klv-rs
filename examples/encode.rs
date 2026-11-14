//! Build one of each kind of group and print it as hex. The groups are the
//! examples of SMPTE ST 336:2017 Annexes C to G, so the output can be
//! checked against the standard.
//!
//!     cargo run --example encode
//!     cargo run --example encode -- out.klv     # also write them to a file

use smpte_klv::{
    DefinedLengthPackEncoder, Error, GlobalSetEncoder, LocalSetEncoder, Triplets, UniversalLabel, UniversalSetEncoder,
    VariableLengthPackEncoder,
};

fn ul(s: &str) -> UniversalLabel {
    s.parse().expect("a valid label")
}

fn main() -> Result<(), Error> {
    let main_title = ul("06.0E.2B.34.01.01.01.01.01.05.02.00.00.00.00.00");
    let version_title = ul("06.0E.2B.34.01.01.01.02.01.05.08.00.00.00.00.00");
    let source_org = ul("06.0E.2B.34.01.01.01.01.02.01.01.00.00.00.00.00");
    let items: [(UniversalLabel, &[u8]); 3] =
        [(main_title, b"Yesterdays World"), (version_title, b"International Edition"), (source_org, b"WXYZ15")];

    let mut universal = UniversalSetEncoder::new(ul("06.0E.2B.34.02.01.01.01.0F.01.01.01.00.00.00.00"))?;
    let mut global = GlobalSetEncoder::new(ul("06.0E.2B.34.02.02.08.01.06.0E.2B.34.01.01.01.00"))?;
    let mut local = LocalSetEncoder::new(ul("06.0E.2B.34.02.03.01.01.0F.01.01.01.00.00.00.00"))?;
    let mut vl_pack = VariableLengthPackEncoder::new(ul("06.0E.2B.34.02.04.01.01.0F.01.01.01.00.00.00.00"))?;
    for (tag, (key, value)) in (1..).zip(items) {
        universal.item(key, value)?;
        global.item(key, value)?;
        local.item(tag, value)?;
        vl_pack.item(value)?;
    }
    let mut dl_pack = DefinedLengthPackEncoder::new(ul("06.0E.2B.34.02.05.01.01.0F.01.01.02.00.00.00.00"))?;
    dl_pack.item(&[3]).item(b"Yesterdays World");

    let packets = [
        ("Universal Set (Annex C)", universal.finish()?),
        ("Global Set (Annex D)", global.finish()?),
        ("Local Set (Annex E)", local.finish()?),
        ("Variable-Length Pack (Annex F)", vl_pack.finish()?),
        ("Defined-Length Pack (Annex G)", dl_pack.finish()?),
    ];
    for (name, bytes) in &packets {
        println!("{name}, {} bytes:", bytes.len());
        for line in bytes.chunks(16) {
            let hex: Vec<String> = line.iter().map(|b| format!("{b:02X}")).collect();
            println!("  {}", hex.join(" "));
        }
    }

    let all: Vec<u8> = packets.iter().flat_map(|(_, b)| b.iter().copied()).collect();
    assert_eq!(Triplets::new(&all).count(), packets.len());
    if let Some(path) = std::env::args().nth(1) {
        std::fs::write(&path, &all).expect("write the output file");
        println!("wrote {} bytes to {path}", all.len());
    }
    Ok(())
}
