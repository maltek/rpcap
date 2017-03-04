
use std::io;

use super::def;
use super::PcapError;
use super::CapturedPacket;


/// The options for creating a new packet capture file.
#[derive(Copy,Clone)]
pub struct WriteOptions {
    /// The maximum size of a packet that can be written to the file.
    pub snaplen : usize,
    /// The type of packets that will be written to the file. See `Linktype` for known values.
    pub linktype : u32,
}

/// The `PcapReader` struct allows reading packets from a packet capture.
pub struct PcapWriter<W : io::Write> {
    writer: W,
    opts: WriteOptions,
}


impl<W : io::Write> PcapWriter<W> {
    /// Create a new `PcapWriter` that writes the packet capture data to the specified `Write`.
    pub fn new(mut writer: W, opts: WriteOptions) -> Result<Self, PcapError> {
        let fh = def::PcapFileHeaderInFile::new(opts.snaplen, opts.linktype)
            .ok_or(PcapError::InvalidFileHeader)?;
        def::write_file_header(&mut writer, &fh)?;

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
        let sec = packet.time.sec as u32;
        let nsec = packet.time.nsec as u32;
        if sec as i64 != packet.time.sec || nsec as i32 != packet.time.nsec {
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

        def::write_record_header(&mut self.writer, &record_header).map_err(PcapError::from)?;
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
}

#[cfg(test)]
mod test {
    use std::io::{BufWriter, BufReader, Write};
    use std::fs::File;
    use super::PcapWriter;
    use super::super::read::PcapReader;

    #[test]
    fn parse() {
        {
            let infile = File::open("ictf2010.pcap").unwrap();
            let reader = BufReader::new(infile);
            let mut pcapr = PcapReader::new(reader).unwrap();

            let outfile = File::create("/tmp/foo.pcap").unwrap();
            let writer = BufWriter::new(outfile);
            let mut pcapw = PcapWriter::new(writer, super::WriteOptions {
                snaplen: pcapr.get_snaplen(),
                linktype: pcapr.get_linktype()
            }).unwrap();

            assert!(pcapr.get_linktype() == super::super::Linktype::RAW.into());
            while let Some(packet) = pcapr.next().unwrap() {
                pcapw.write(&packet).unwrap();
            }
            pcapw.take_writer().flush().unwrap();
        }

        let reference = File::open("ictf2010.pcap").unwrap();
        let reader = BufReader::new(reference);
        let mut pcapr = PcapReader::new(reader).unwrap();

        let written = File::open("/tmp/foo.pcap").unwrap();
        let reader = BufReader::new(written);
        let mut pcapw = PcapReader::new(reader).unwrap();

        assert_eq!(pcapr.get_linktype(), pcapw.get_linktype());
        assert_eq!(pcapr.get_snaplen(), pcapw.get_snaplen());
        while let Some(packetr) = pcapr.next().unwrap() {
            let packetw = pcapw.next().unwrap().unwrap();
            assert_eq!(packetr.time, packetw.time);
            assert_eq!(packetr.orig_len, packetw.orig_len);
            assert_eq!(packetr.data, packetw.data);
        }
        assert!(pcapw.next().unwrap().is_none());
    }
}
