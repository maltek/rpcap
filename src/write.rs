
use std::io;
#[cfg(not(feature = "time"))]
use std::time::UNIX_EPOCH;

use super::def;
use super::PcapError;
use super::CapturedPacket;
use super::Time;

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

        PcapWriter::append_unchecked(writer, opts)
    }
    /// Create a new `PcapWriter` that appends the packets to an existing `Write`. If the
    /// `WriteOptions` specified here are different than those used to create the file, the
    /// resulting file will be invalid.
    ///
    /// *Warning:* Only append to created using `PcapWriter::new` on the same machine. Files
    /// created on other architectures or from another tool/library might use different
    /// timestamp formats or endianness, leading to data corruption.
    pub fn append_unchecked(writer: W, opts: WriteOptions) -> Result<Self, PcapError> {
        Ok(PcapWriter { writer, opts, })
    }

    /// Create a new `PcapWriter` that appends the packets to an existing stream, which must
    /// support `Read + Write + Seek` so that the correct format options for the file can be
    /// determined.
    pub fn append(mut stream: W) -> Result<Self, PcapError>
        where W: io::Read + io::Seek
    {
        stream.seek(io::SeekFrom::Start(0))?;
        let (opts, reader) = super::read::PcapReader::new(stream)?;

        let mut writer = reader.take_reader();
        writer.seek(io::SeekFrom::End(0))?;

        Ok(PcapWriter { writer, opts, })
    }

    /// Write a package to the capture file.
    pub fn write(&mut self, packet: &CapturedPacket) -> Result<(), PcapError> {
        let duration = secs_since_epoch(packet.time);
        let (sec, nsec) = match duration {
            Some((sec, nsec)) => (sec, nsec),
            None => return Err(PcapError::InvalidDate),
        };

        let len = packet.data.len() as u32;
        let orig_len = packet.orig_len as u32;
        if packet.data.len() > self.opts.snaplen || len as usize != packet.data.len() ||
           orig_len as usize != packet.orig_len {
            return Err(PcapError::InvalidPacketSize);
        }

        let record_header = def::PcapRecordHeader {
            // TODO: We might want to support low-res timestamps at some point.
            ts_sec: sec,
            ts_usec: nsec,
            incl_len: len,
            orig_len,
        };

        // TODO: We might want to support for writing files in non-native endianness at some point.

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
#[cfg(not(feature = "time"))]
fn secs_since_epoch(time: Time) -> Option<(u32, u32)> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    let sec = duration.as_secs().try_into().ok()?;
    let nsec = duration.subsec_nanos();
    Some((sec, nsec))
}
#[cfg(feature = "time")]
fn secs_since_epoch(time: Time) -> Option<(u32, u32)> {
    let sec = time.sec.try_into().ok()?;
    let nsec = time.nsec.try_into().ok()?;
    Some((sec, nsec))
}
