use super::read::PcapReader;
use super::{PcapError, FileOptions};
use super::write::PcapWriter;
use std::io::Cursor;

use super::Time;

#[cfg(not(feature = "time"))]
fn time_diff_millis(t1: Time, t2: Time) -> u128 {
    t1.duration_since(t2).unwrap_or_else(|te| te.duration()).as_millis()
}
#[cfg(feature = "time")]
fn time_diff_millis(t1: Time, t2: Time) -> i64 {
    (t1 - t2).num_milliseconds().abs()
}

fn compare(buf1: &[u8], expected_opts1: FileOptions, buf2: &[u8], expected_opts2: FileOptions, expected: Vec<Result<(), ()>>) {
    let (ropts1, mut pcapr1) = PcapReader::new(buf1).unwrap();
    let (ropts2, mut pcapr2) = PcapReader::new(buf2).unwrap();
    assert_eq!(expected_opts1, ropts1);
    assert_eq!(expected_opts2, ropts2);
    for state in expected {
        let p1 = pcapr1.next().unwrap().unwrap();
        if state.is_ok() {
            let mut p2 = pcapr2.next().unwrap().unwrap();
            if ropts1.high_res_timestamps && !ropts2.high_res_timestamps {
                assert!(time_diff_millis(p1.time, p2.time) <= 1);
                p2.time = p1.time;
            }
            assert_eq!(p1, p2);
        }
    }
    assert_eq!(None, pcapr2.next().unwrap());
}

pub fn fuzz(data: &[u8]) {
    if data.is_empty() { return; }

    let (random, data) = data.split_last().unwrap();

    if let Ok((opts, mut pcapr)) = PcapReader::new(data) {
        let mut buf = vec![0; data.len()];

        let mut write_opts = opts;
        if (random & 1) != 0 {
            write_opts.high_res_timestamps = !write_opts.high_res_timestamps;
        }
        if (random & 3) != 0 {
            write_opts.non_native_byte_order = !write_opts.non_native_byte_order;
        }

        // the cursor with &mut [u8] avoids unbounded resizing of the buffer for invalid size fields
        let mut pcapw: PcapWriter<Cursor<&mut [u8]>> = PcapWriter::new(Cursor::new(buf.as_mut()), write_opts).unwrap();

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

        compare(data.as_ref(), opts, buf.as_ref(), write_opts, written);
    }
}
