#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rpcap;

use rpcap::read::PcapReader;
use rpcap::PcapError;
use rpcap::write::PcapWriter;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if let Ok((opts, mut pcapr)) = PcapReader::new(data) {
        let mut buf = vec![0; data.len()];
        // the cursor with &mut [u8] avoids unbounded resizing of the buffer for invalid size fields
        let mut pcapw: PcapWriter<Cursor<&mut [u8]>> = PcapWriter::new(Cursor::new(buf.as_mut()), opts).unwrap();

        let mut written = Vec::new();

        while let Ok(Some(packet)) = pcapr.next() {
            match pcapw.write(&packet) {
                Err(PcapError::InvalidDate) => written.push(Err(())), // TODO
                res => {
                    res.unwrap();
                    written.push(Ok(()));
                }
            }
        }

        let cursor = pcapw.take_writer();
        let size = cursor.position() as usize;
        let buf = &cursor.into_inner()[..size];

        let (ropts1, mut pcapr1) = PcapReader::new(data).unwrap();
        let (ropts2, mut pcapr2) = PcapReader::new(buf.as_ref()).unwrap();
        assert_eq!(ropts1.snaplen, ropts2.snaplen);
        assert_eq!(ropts1.linktype, ropts2.linktype);
        for state in written {
            let p1 = pcapr1.next().unwrap().unwrap();
            if state.is_ok() {
                assert_eq!(p1, pcapr2.next().unwrap().unwrap());
            }
        }
        assert_eq!(None, pcapr2.next().unwrap());
    }
});
