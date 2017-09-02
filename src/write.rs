
use std::io;
use std::time::UNIX_EPOCH;

use super::def;
use super::PcapError;
use super::CapturedPacket;

use bytepack::Packer;


/// The options for creating a new packet capture file.
#[derive(Copy,Clone)]
pub struct WriteOptions {
    /// The maximum size of a packet that can be written to the file.
    pub snaplen: usize,
    /// The type of packets that will be written to the file. See `Linktype` for known values.
    pub linktype: u32,
}

/// The `PcapReader` struct allows reading packets from a packet capture.
pub struct PcapWriter<W: io::Write> {
    writer: W,
    opts: WriteOptions,
}

impl<W: io::Write> PcapWriter<W> {
    /// Create a new `PcapWriter` that writes the packet capture data to the specified `Write`.
    pub fn new(mut writer: W, opts: WriteOptions) -> Result<Self, PcapError> {
        let fh = def::PcapFileHeaderInFile::new(opts.snaplen, opts.linktype)
            .ok_or(PcapError::InvalidFileHeader)?;
        writer.pack(fh)?;

        PcapWriter::append(writer, opts)
    }
    /// Create a new `PcapWriter` that appends the packets to an existing `Write`. If the
    /// `WriteOptions` specified here are different than those used to create the file, the
    /// resulting file will be invalid.
    pub fn append(writer: W, opts: WriteOptions) -> Result<Self, PcapError> {
        Ok(PcapWriter {
            writer: writer,
            opts: opts,
        })
    }

    /// Write a package to the capture file.
    pub fn write(&mut self, packet: &CapturedPacket) -> Result<(), PcapError> {
        let duration = packet.time.duration_since(UNIX_EPOCH)?;
        let sec = duration.as_secs() as u32;
        let nsec = duration.subsec_nanos();
        if sec as u64 != duration.as_secs() {
            return Err(PcapError::InvalidDate);
        }

        let len = packet.data.len() as u32;
        let orig_len = packet.orig_len as u32;
        if packet.data.len() > self.opts.snaplen || len as usize != packet.data.len() ||
           orig_len as usize != packet.orig_len {
            return Err(PcapError::InvalidPacketSize);
        }

        let record_header = def::PcapRecordHeader {
            ts_sec: sec,
            ts_usec: nsec,
            incl_len: len,
            orig_len: orig_len,
        };

        self.writer.pack(record_header)?;
        self.writer.write_all(packet.data).map_err(PcapError::from)
    }

    /// Flushes the underlying writer.
    pub fn flush(&mut self) -> Result<(), io::Error> {
        self.writer.flush()
    }

    /// Destroys this `PcapWriter` and returns access to the underlying `Write`.
    pub fn take_writer(self) -> W {
        self.writer
    }

    /// The options used by this `PcapWriter`.
    pub fn get_options(&self) -> WriteOptions {
        self.opts
    }
}
