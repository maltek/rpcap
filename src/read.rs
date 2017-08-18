
use std::io;

use super::def;
use super::PcapError;
use super::CapturedPacket;

use bytepack::Unpacker;

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
            Some(state) => state.packet_buffer.len()
        }
    }
    /// This function allows iterating over the packets in the packet capture, in a similar fashion
    /// to normal iterators. (The exact interface is unfortunately incompatible.)
    /// 
    /// Returns `Ok(None)` on EOF, or a packet as long as one is available.
    #[allow(should_implement_trait,unknown_lints)]
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
                Err(PcapError::from(e))
            };
        }
        let mut rh = rh.unwrap();
        let state = self.state.as_mut().unwrap();
        rh.swap_bytes(&state.file_header);

        let mut toread = rh.incl_len as usize;
        if state.packet_buffer.capacity() < toread {
            while toread > state.packet_buffer.capacity() {
                let cnt = self.reader.read(state.packet_buffer.as_mut_slice())?;
                if cnt == 0 {
                    return Err(PcapError::InvalidPacketSize);
                }
                toread -= cnt;
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
