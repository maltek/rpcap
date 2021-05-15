//! This crate has functionality for reading and writing packet capture packet files in the
//! traditional libpcap file format. There is no support for the newer pcapng file format.
//!
//! Please note that there is no functionality for capturing live packets from a network interface,
//! this library only handles reading/writing data in the pcap file format.


extern crate bytepack;
#[cfg(feature = "time")]
extern crate time;


mod def;
/// Functionality for reading a packet capture.
pub mod read;
/// Functionality for writing packet captures.
pub mod write;

#[cfg(fuzzing)]
pub mod fuzz;

pub use def::Linktype;

#[cfg(not(feature = "time"))]
use std::time::SystemTime as Time;
#[cfg(feature = "time")]
use time::Timespec as Time;



use std::error;
use std::fmt;
use std::io;


/// The `CapturedPacket` struct contains information about a single captured packet.
#[derive(Eq,PartialEq,Debug)]
pub struct CapturedPacket<'a> {
    /// The time when the packet was captured.
    pub time: Time,
    /// The contents of the packet (possibly truncated to `orig_len` bytes during capture).
    /// Depending on the [`Linktype`](enum.Linktype.html) of the capture, there might be completely
    /// different data in this packet. The user of this library is responsible for interpreting the
    /// contents correctly.
    pub data: &'a [u8],
    /// The size of the packet as it was on the wire. Might be larger than the size of `data`, in
    /// which case `data` was truncated and is incomplete.
    pub orig_len: usize,
}

/// The options for packet capture files.
#[derive(Copy,Clone,PartialEq,Eq,Debug)]
pub struct FileOptions {
    /// The maximum size of a packet in the file.
    ///
    /// Packets larger than this usually get truncated to this size by the recording application.
    pub snaplen: usize,
    /// The type of packets in the file. See `Linktype` for known values.
    pub linktype: u32,
    /// Determines the timestamp format of packets the file.
    pub high_res_timestamps: bool,
    /// Determines the byte order for the file headers.
    pub non_native_byte_order: bool,
}


/// The error type for this crate.
#[derive(Debug)]
pub enum PcapError {
    /// An error that was returned by the underlying reader/writer.
    ///
    /// Possible recovery depends on the underlying reader/writer.
    Io(io::Error),
    /// A packet could not be returned because it's size exceeds that specified in the pcap file
    /// header, or that of the target architecture's `usize`.
    ///
    /// You can try recovering by reading the next packet, but it is likely the pcap file is
    /// corrupted.
    InvalidPacketSize,
    /// A packet could not be returned because it has an invalid timestamp.
    ///
    /// You can try recovering by reading the next packet, but it is likely the pcap file is
    /// corrupted.
    InvalidDate,
    /// The pcap file header could not be parsed.
    InvalidFileHeader,
}
impl From<io::Error> for PcapError {
    fn from(err: io::Error) -> PcapError {
        PcapError::Io(err)
    }
}
impl From<std::time::SystemTimeError> for PcapError {
    fn from(_: std::time::SystemTimeError) -> PcapError {
        PcapError::InvalidDate
    }
}
impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = match *self {
            PcapError::Io(ref err) => { return err.fmt(f); },
            PcapError::InvalidPacketSize => "Parsed packet has an invalid size.",
            PcapError::InvalidDate => "Parsed packet has an invalid date.",
            PcapError::InvalidFileHeader => "The pcap file has an invalid/unknown file header.",
        };
        write!(f, "{}", desc)
    }
}
impl error::Error for PcapError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            PcapError::Io(ref err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Write};

    use super::write::{PcapWriter, WriteOptions};
    use super::read::PcapReader;
    use super::Time;
    use super::{CapturedPacket, Linktype};

    #[cfg(not(feature = "time"))]
    use ::std::time::{Duration, UNIX_EPOCH};

    extern crate rand;
    use self::rand::Rng;

    /// Generates 10 buffers with random data.
    fn gen_packet_data() -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        (0..10)
            .map(|_| {
                let size = rng.gen_range::<usize>(0, 2000);
                rng.gen_iter::<u8>().take(size).collect()
            })
            .collect()
    }

    #[cfg(not(feature = "time"))]
    fn make_time(secs: u64, nsecs: u32) -> Time {
        UNIX_EPOCH + Duration::new(secs, nsecs)
    }
    #[cfg(feature = "time")]
    fn make_time(secs: u64, nsecs: u32) -> Time {
        Time::new(secs as i64, nsecs as i32)
    }

    /// Generates a random packet for every buffer in `contents`.
    fn gen_packets<'a>(contents: &'a Vec<Vec<u8>>, snaplen: usize) -> Vec<CapturedPacket<'a>> {
        let mut rng = rand::thread_rng();

        contents.iter()
            .map(|data| {
                let s = rng.gen_range::<u64>(0, u64::from(u32::max_value()) + 1);
                let ns = rng.gen_range::<u32>(0, 1_000_000_000);

                CapturedPacket {
                    time: make_time(s, ns),
                    data: &data.chunks(snaplen).next().unwrap(),
                    orig_len: data.len(),
                }
            })
            .collect()
    }

    /// Writes `packets` to the `writer`. Returns the underlying writer of `writer`.
    fn write_packets<W: Write>(mut writer: PcapWriter<W>, packets: &[CapturedPacket]) -> W {
        for p in &packets[..packets.len()] {
            writer.write(&p).unwrap();
        }
        writer.take_writer()
    }

    #[test]
    fn read_write() {
        const MAX_PACKET_SIZE : usize = 1000;

        let contents = gen_packet_data();
        let packets = gen_packets(&contents, MAX_PACKET_SIZE);

        let opts = WriteOptions {
            high_res_timestamps: true,
            non_native_byte_order: false,
            snaplen: MAX_PACKET_SIZE,
            linktype: Linktype::NULL.into(),
        };

        let buf = write_packets(PcapWriter::new(Vec::new(), opts).unwrap(), &packets[..packets.len()/2]);
        let buf = PcapWriter::append(Cursor::new(buf)).unwrap();
        let buf = write_packets(buf, &packets[packets.len()/2..]).into_inner();

        let (ropts, mut reader) = PcapReader::new(buf.as_slice()).unwrap();
        assert_eq!(opts, ropts);
        for expect in packets {
            let actual = reader.next().unwrap().unwrap();
            assert_eq!(actual, expect);
        }
        assert!(reader.next().unwrap().is_none());
    }
}
