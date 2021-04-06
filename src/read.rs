
use std::io;
use std::convert::TryFrom;

use super::def;
use super::PcapError;
use super::CapturedPacket;

use bytepack::{Unpacker, Packed};

/// The `PcapReader` struct allows reading packets from a packet capture.
pub struct PcapReader<R> {
    reader: R,
    network: u32,
    state: Option<PcapState>,
}
struct PcapState {
    file_header: def::PcapFileHeader,
    packet_buffer: Vec<u8>,
}


impl<R: io::Read> PcapReader<R> {
    /// Create a new `PcapReader` that reads the packet capture data from the specified `Reader`.
    pub fn new(mut reader: R) -> Result<Self, PcapError> {
        let fh = reader.unpack::<def::PcapFileHeaderInFile>()?;
        let fh = def::PcapFileHeader::try_from(fh).ok_or(PcapError::InvalidFileHeader)?;

        let buffer = vec![0; fh.snaplen.into()];
        Ok(PcapReader {
            reader: reader,
            network: fh.network,
            state: Some(PcapState {
                file_header: fh,
                packet_buffer: buffer,
            }),
        })
    }
    /// Returns the link type of this packet capture. See `Linktype` for the known values.
    pub fn get_linktype(&self) -> u32 {
        self.network
    }
    /// Returns the maximum packet size. Packets larger than this usually get truncated to this
    /// size by the recording application.
    pub fn get_snaplen(&self) -> usize {
        match self.state.as_ref() {
            None => 0,
            Some(state) => state.packet_buffer.len(),
        }
    }
    /// This function allows iterating over the packets in the packet capture, in a similar fashion
    /// to normal iterators. (The exact interface is unfortunately incompatible.)
    ///
    /// Returns `Ok(None)` on EOF, or a packet as long as one is available.
    #[allow(unknown_lints,should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<CapturedPacket>, PcapError> {
        if self.state.is_none() {
            return Ok(None);
        }

        let rh = self.reader.unpack::<def::PcapRecordHeader>();
        if let Err(e) = rh {
            return if e.kind() == io::ErrorKind::UnexpectedEof {
                self.state = None;
                Ok(None)
            } else {
                Err(e.into())
            };
        }
        let mut rh = rh.unwrap();
        let state = self.state.as_mut().unwrap();
        if state.file_header.need_byte_swap {
            rh.switch_endianness();
        }

        let size_in_pcap = usize::try_from(rh.incl_len).or(Err(PcapError::InvalidPacketSize))?;
        let size_to_read = usize::min(state.packet_buffer.len(), size_in_pcap);

        let buf = &mut state.packet_buffer[..size_to_read];
        self.reader.read_exact(buf)?;

        if size_to_read < size_in_pcap {
            // we used to return InvalidPacketSize here, now we just drop the excessive data
            let mut take = self.reader.by_ref().take((size_in_pcap - size_to_read) as u64);
            io::copy(&mut take, &mut io::sink())?;
        }

        let orig_len = usize::try_from(rh.orig_len).or(Err(PcapError::InvalidPacketSize))?;

        if let Some(t) = rh.get_time(&state.file_header) {
            Ok(Some(CapturedPacket {
                time: t,
                data: buf,
                orig_len,
            }))
        } else {
            Err(PcapError::InvalidDate)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// Makes sure that PCAPs with identical contents but different endianness and
    /// timestamp formats parse identical.
    fn format_variations() {
        let be_us = [0xa1, 0xb2, 0x3c, 0x4d, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x65, 0x56, 0x50,
                     0x6e, 0x1a, 0x18, 0x2b, 0x0a, 0xd0, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                     0x3c, 0x44, 0x41, 0x54, 0x41];
        let be_ns = [0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x65, 0x56, 0x50,
                     0x6e, 0x1a, 0x00, 0x06, 0x2f, 0xe2, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                     0x3c, 0x44, 0x41, 0x54, 0x41];
        let le_us = [0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x1a, 0x6e,
                     0x50, 0x56, 0xe2, 0x2f, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00,
                     0x00, 0x44, 0x41, 0x54, 0x41];
        let le_ns: [u8; 44] = [0x4d, 0x3c, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x65, 0x00,
                               0x00, 0x00, 0x1a, 0x6e, 0x50, 0x56, 0xd0, 0x0a, 0x2b, 0x18, 0x04,
                               0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x44, 0x41, 0x54, 0x41];
        let raw_pcaps = [be_ns, be_us, le_ns, le_us];
        let mut readers: Vec<PcapReader<&[u8]>> = raw_pcaps.iter()
            .map(|pcap| PcapReader::new(pcap as &[u8]).unwrap())
            .collect();

        {
            let mut packets = readers.iter_mut().map(|r| r.next().unwrap().unwrap());
            let first: CapturedPacket = packets.next().unwrap();
            for packet in packets {
                assert_eq!(first, packet);
            }
        }

        for r in &mut readers {
            assert!(r.next().unwrap().is_none());
        }
    }
}
