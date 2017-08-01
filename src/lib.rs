//! This crate has functionality for reading and writing packet capture packet files in the
//! traditional libpcap file format. There is no support for the newer pcapng file format.
//! 
//! Please note that there is no functionality for capturing live packets from a network interface,
//! this library only handles reading/writing data in the pcap file format.


extern crate time;

extern crate bytepack;
#[macro_use]
extern crate bytepack_derive;


mod def;
/// Functionality for reading a packet capture.
pub mod read;
/// Functionality for writing packet captures.
pub mod write;

pub use def::Linktype;



use std::error;
use std::error::Error;
use std::fmt;
use std::io;


/// The `CapturedPacket` struct contains information about a single captured packet.
#[derive(Eq,PartialEq,Debug)]
pub struct CapturedPacket<'a> {
    /// The time when the packet was captured.
    pub time: time::Timespec,
    /// The contents of the packet (possibly truncated to `orig_len` bytes during capture).
    /// Depending on the `Linktype` of the capture, there might be completely different data in
    /// this packet. The user of this library is responsible for interpreting the contents
    /// correctly.
    pub data: &'a [u8],
    /// The size of the packet as it was on the wire. Might be larger than the size of `data`, in
    /// which case `data` was truncated and is incomplete.
    pub orig_len: usize,
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
impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}
impl error::Error for PcapError {
    fn description(&self) -> &str {
        match *self {
            PcapError::Io(ref err) => err.description(),
            PcapError::InvalidPacketSize => "Parsed packet has an invalid size.",
            PcapError::InvalidDate => "Parsed packet has an invalid date.",
            PcapError::InvalidFileHeader => "The pcap file has an invalid/unknown file header.",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            PcapError::Io(ref err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use super::write::{PcapWriter, WriteOptions};
    use super::read::PcapReader;
    use super::{CapturedPacket, Linktype};

    use super::time::Timespec;

    extern crate rand;
    use self::rand::Rng;

    /// Generates 10 buffers with random data.
    fn gen_packet_data() -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        (0..10).map(|_| {
            let size = rng.gen_range::<usize>(0, 2000);
            rng.gen_iter::<u8>().take(size).collect()
        }).collect()
    }

    /// Generates a random packet for every buffer in `contents`.
    fn gen_packets<'a>(contents: &'a Vec<Vec<u8>>, snaplen: usize) -> Vec<CapturedPacket<'a>> {
        let mut rng = rand::thread_rng();

        contents.iter().map(|data| {
            let s = rng.gen_range::<i64>(0, i64::from(u32::max_value()) + 1);
            let ns = rng.gen_range::<i32>(0, 1_000_000_000);

            CapturedPacket {
                time: Timespec::new(s, ns),
                data: &data.chunks(snaplen).next().unwrap(),
                orig_len: data.len(),
            }
        }).collect()
    }

    /// Writes `packets` to the `writer`. Returns the underlying writer of `writer`.
    fn write_packets<W: Write>(mut writer: PcapWriter<W>, packets: &[CapturedPacket]) -> W {
        for p in &packets[..5] {
            writer.write(&p).unwrap();
        }
        writer.take_writer()
    }

    #[test]
    fn read_write() {
        let contents = gen_packet_data();
        let packets = gen_packets(&contents, 1000);

        let opts = WriteOptions {
            snaplen: 1000,
            linktype: Linktype::NULL.into(),
        };

        let mut buf = write_packets(PcapWriter::new(Vec::new(), opts).unwrap(), &packets[..5]);
        buf = write_packets(PcapWriter::append(buf, opts).unwrap(), &packets[5..]);

        let mut reader = PcapReader::new(buf.as_slice()).unwrap();
        assert_eq!(reader.get_linktype(), Linktype::NULL.into());
        assert_eq!(reader.get_snaplen(), 1000);
        let mut i = 0;
        while let Some(packet) = reader.next().unwrap() {
            assert_eq!(packet, packets[i]);
            i += 1;
        }
        assert_eq!(i, packets.len());
    }
}
