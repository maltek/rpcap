//! This crate has functionality for reading and writing packet capture packet files in the
//! traditional libpcap file format. There is no support for the newer pcapng file format.
//! 
//! Please see the test cases for example usage.


extern crate time;

mod def;
/// Functionality for reading a packet capture.
pub mod read;
pub use def::Linktype;



use std::error;
use std::error::Error;
use std::fmt;
use std::io;


/// The `CapturedPacket` struct contains information about a single captured packet.
pub struct CapturedPacket<'a> {
    /// The time when the packet was captured.
    pub time: time::Timespec,
    /// The contents of the packet (possibly truncated to `orig_len` bytes during capture).
    /// Depending on the `Linktype` of the capture, there might be completely different data in
    /// this packet. The user of this library is responsible for interpreting the contents
    /// correctly.
    pub data: &'a mut [u8],
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
