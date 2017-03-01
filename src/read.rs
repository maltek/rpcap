
use std::io;

use super::def;
use super::PcapError;
use super::CapturedPacket;

/// The `PcapReader` struct allows reading packets from a packet capture.
pub struct PcapReader<R : io::Read> {
    reader: R,
    network: u32,
    state: Option<PcapState>,
}
struct PcapState {
    file_header: def::PcapFileHeader,
    packet_buffer: Vec<u8>,
}



impl<R : io::Read> PcapReader<R> {
    /// Create a new `PcapReader` that reads the packet capture data from the specified `Reader`.
    pub fn new(mut reader: R) -> Result<Self, PcapError> {
        let fh = def::read_file_header(&mut reader)?.ok_or(PcapError::InvalidFileHeader)?;

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
    /// This function allows iterating over the packets in the packet capture, in a similar fashion
    /// to normal iterators. (The exact interface is unfortunately incompatible.)
    /// 
    /// Returns `Ok(None)` on EOF, or a packet as long as one is available.
    pub fn next<'a>(&'a mut self) -> Result<Option<CapturedPacket<'a>>, PcapError> {
        if self.state.is_none() {
            return Ok(None);
        }

        let rh = def::read_record_header(&mut self.reader);
        if let Err(e) = rh {
            return if e.kind() == io::ErrorKind::UnexpectedEof {
                self.state = None;
                Ok(None)
            } else {
                Err(PcapError::from(e))
            };
        }
        let mut rh = rh.unwrap();
        let state = self.state.as_mut().unwrap();
        rh.swap_bytes(&state.file_header);

        let mut toread = rh.incl_len as usize;
        if state.packet_buffer.capacity() < toread {
            while toread > state.packet_buffer.capacity() {
                self.reader.read_exact(state.packet_buffer.as_mut_slice())?;
                toread -= state.packet_buffer.capacity();
            }
            self.reader.read_exact(&mut state.packet_buffer[..toread])?;
            return Err(PcapError::InvalidPacketSize);
        }

        let buf = &mut state.packet_buffer[..toread];
        self.reader.read_exact(buf)?;

        let orig_len = rh.orig_len as usize;
        if orig_len as u32 != rh.orig_len {
            return Err(PcapError::InvalidPacketSize);
        }

        if let Some(t) = rh.get_time(&state.file_header) {
            Ok(Some(CapturedPacket { time: t, data: buf, orig_len: orig_len }))
        } else {
            Err(PcapError::InvalidDate)
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::BufReader;
    use std::fs::File;
    use super::PcapReader;

    #[test]
    fn parse() {
        let file = File::open("/mnt/DATEN/ructfe2016/dump-ructfe-2016_2016-11-12_13:14:41.pcap").unwrap();
        let reader = BufReader::new(file);
        let mut pcap = PcapReader::new(reader).unwrap();
        let mut count = 0;
        assert!(pcap.get_linktype() == super::super::Linktype::RAW.into());
        while let Some(_) = pcap.next().unwrap() {
            count += 1;
        }
        assert!(count == 24);
    }
}
