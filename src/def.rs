use bytepack::Packed;

#[cfg(not(feature = "time"))]
use std::time::{Duration, UNIX_EPOCH};

use super::{FileOptions, Time};

use std::convert::{TryFrom,TryInto};



/// The serialized file header data.
#[repr(C,packed)]
pub struct PcapFileHeaderInFile {
    /// magic number
    pub magic_num: u32,
    /// major version number
    pub version_major: u16,
    /// minor version number
    pub version_minor: u16,
    /// GMT to local correction
    pub thiszone: i32,
    /// accuracy of timestamps
    pub sigfigs: u32,
    /// max length of captured packets, in octets
    pub snaplen: u32,
    /// data link type
    pub network: u32,
}

/// only supported major version
const PCAP_VERSION_MAJOR: u16 = 2;
/// only supported minor version
const PCAP_VERSION_MINOR: u16 = 4;

impl PcapFileHeaderInFile {
    /// Creates a new file header based on snap length and link type.
    pub fn new(opts: FileOptions) -> Option<PcapFileHeaderInFile> {
        let magic = if opts.high_res_timestamps {
            PcapMagic::NanoSecondResolution
        } else {
            PcapMagic::Normal
        };
        Some(PcapFileHeaderInFile {
            magic_num: magic.into(),
            version_major: PCAP_VERSION_MAJOR,
            version_minor: PCAP_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen: u32::try_from(opts.snaplen).ok()?,
            network: opts.linktype,
        })
    }
}
impl Packed for PcapFileHeaderInFile {
    fn switch_endianness(&mut self) {
        self.magic_num = self.magic_num.swap_bytes();
        self.version_major = self.version_major.swap_bytes();
        self.version_minor = self.version_minor.swap_bytes();
        self.thiszone = self.thiszone.swap_bytes();
        self.sigfigs = self.sigfigs.swap_bytes();
        self.snaplen = self.snaplen.swap_bytes();
        self.network = self.network.swap_bytes();
    }
}

/// Fully parsed file header data.
pub struct PcapFileHeader {
    /// `true`, if the timestamp has nanosecond resolution (as opposed to microsecond resolution)
    pub ns_res: bool,
    /// `true`, if header values need to be byte swapped when they are read from the file
    pub need_byte_swap: bool,
    /// The datalink type.
    pub network: u32,
    /// The UTC offset of the timestamps.
    pub utc_offset: i32,
    /// The maximum size of captured packets.
    pub snaplen: usize,
}
impl TryFrom<PcapFileHeaderInFile> for PcapFileHeader {
    type Error = ();

    /// Parse header data from file.
    fn try_from(mut header: PcapFileHeaderInFile) -> Result<Self, Self::Error> {
        let magic = PcapMagic::try_from(header.magic_num)?;

        if magic.need_byte_swap() {
            header.switch_endianness();
        }

        let snaplen = usize::try_from(header.snaplen).or(Err(()))?;

        // docs say this version number hasn't changed since 1998, so this simplistic comparison
        // should suffice
        if header.version_major == PCAP_VERSION_MAJOR &&
           header.version_minor == PCAP_VERSION_MINOR {
            Ok(PcapFileHeader {
               ns_res: magic.ns_res(),
               need_byte_swap: magic.need_byte_swap(),
               network: header.network,
               utc_offset: header.thiszone,
               snaplen,
            })
        } else {
            Err(())
        }
    }
}


/// The different magic numbers for PCAP files.
#[repr(u32)]
#[allow(dead_code)]
#[derive(Copy,Clone)]
enum PcapMagic {
    /// same byte order as in memory, timestamps with microsecond resolution
    Normal = 0xa1b2_c3d4,
    /// same byte order as in memory, timestamps with nanosecond resolution
    NanoSecondResolution = 0xa1b2_3c4d,
    /// different byte order than in memory, timestamps with microsecond resolution
    ByteSwap = (Self::Normal as u32).swap_bytes(),
    /// different byte order than in memory, timestamps with nanosecond resolution
    NanoSecondResolutionByteSwap = (Self::NanoSecondResolution as u32).swap_bytes(),
}
impl TryFrom<u32> for PcapMagic {
    type Error = ();

    /// Try to convert a `u32` to a `PcapMagic`.
    fn try_from(val: u32) -> Result<Self, Self::Error> {
        if val == PcapMagic::Normal.into() {
            Ok(PcapMagic::Normal)
        } else if val == PcapMagic::NanoSecondResolution.into() {
            Ok(PcapMagic::NanoSecondResolution)
        } else if val == PcapMagic::ByteSwap.into() {
            Ok(PcapMagic::ByteSwap)
        } else if val == PcapMagic::NanoSecondResolutionByteSwap.into() {
            Ok(PcapMagic::NanoSecondResolutionByteSwap)
        } else {
            Err(())
        }
    }
}
impl PcapMagic {
    /// Does the file use native endianess of our platform?
    fn need_byte_swap(self) -> bool {
        match self {
            PcapMagic::Normal |
            PcapMagic::NanoSecondResolution => false,
            PcapMagic::ByteSwap |
            PcapMagic::NanoSecondResolutionByteSwap => true,
        }
    }
    /// Are timestamps in nanosecond resolution?
    /// true, if the timestamp has nanosecond resolution (as opposed to microsecond resolution)
    fn ns_res(self) -> bool {
        match self {
            PcapMagic::Normal | PcapMagic::ByteSwap => false,
            PcapMagic::NanoSecondResolution |
            PcapMagic::NanoSecondResolutionByteSwap => true,
        }
    }
}
impl From<PcapMagic> for u32 {
    fn from(val: PcapMagic) -> u32 {
        val as u32
    }
}

/// Per-packet header data.
#[repr(C,packed)]
pub struct PcapRecordHeader {
    /// timestamp seconds
    pub ts_sec: u32,
    /// timestamp microseconds (or nanoseconds, depending on the header)
    pub ts_usec: u32,
    /// number of octets of packet saved in file
    pub incl_len: u32,
    /// actual length of packet
    pub orig_len: u32,
}
impl Packed for PcapRecordHeader {
    fn switch_endianness(&mut self) {
        self.ts_sec = self.ts_sec.swap_bytes();
        self.ts_usec = self.ts_usec.swap_bytes();
        self.incl_len = self.incl_len.swap_bytes();
        self.orig_len = self.orig_len.swap_bytes();
    }
}

#[cfg(feature = "time")]
fn make_time(sec: i64, nsec: u32) -> Option<Time> {
    Some(Time::new(sec, nsec.try_into().ok()?))
}
#[cfg(not(feature = "time"))]
fn make_time(sec: i64, nsec: u32) -> Option<Time> {
    UNIX_EPOCH.checked_add(Duration::new(sec.try_into().ok()?, nsec))
}

impl PcapRecordHeader {
    /// Get the time and date of this packet.
    pub fn get_time(&self, file_header: &PcapFileHeader) -> Option<Time> {
        let nsec = if file_header.ns_res {
            self.ts_usec
        } else {
            self.ts_usec.checked_mul(1000)?
        };
        let sec = i64::from(self.ts_sec).checked_add(i64::from(file_header.utc_offset))?;

        if nsec < 1_000_000_000 {
            make_time(sec, nsec)
        } else {
            None
        }
    }
}


/// Known identifiers for the types of packets that might be captured in a `pcap` file. This tells
/// you how to interpret the packets you receive.
///
/// Look at [tcpdump.org](http://www.tcpdump.org/linktypes.html) for the canonical list with
/// descriptions.
#[derive(Copy,Clone)]
#[repr(u32)]
#[allow(dead_code,non_camel_case_types,clippy::upper_case_acronyms)]
pub enum Linktype {
    NULL = 0,
    /// Ethernet packets
    ETHERNET = 1,
    AX25 = 3,
    IEEE802_5 = 6,
    ARCNET_BSD = 7,
    SLIP = 8,
    PPP = 9,
    FDDI = 10,
    PPP_HDLC = 50,
    PPP_ETHER = 51,
    ATM_RFC1483 = 100,
    /// IP packets (IPv4 or IPv6)
    RAW = 101,
    C_HDLC = 104,
    IEEE802_11 = 105,
    FRELAY = 107,
    LOOP = 108,
    LINUX_SLL = 113,
    LTALK = 114,
    PFLOG = 117,
    IEEE802_11_PRISM = 119,
    IP_OVER_FC = 122,
    SUNATM = 123,
    IEEE802_11_RADIOTAP = 127,
    ARCNET_LINUX = 129,
    APPLE_IP_OVER_IEEE1394 = 138,
    MTP2_WITH_PHDR = 139,
    MTP2 = 140,
    MTP3 = 141,
    SCCP = 142,
    DOCSIS = 143,
    LINUX_IRDA = 144,
    USER00_LINKTYPE = 147,
    USER01_LINKTYPE = 148,
    USER02_LINKTYPE = 149,
    USER03_LINKTYPE = 150,
    USER04_LINKTYPE = 151,
    USER05_LINKTYPE = 152,
    USER06_LINKTYPE = 153,
    USER07_LINKTYPE = 154,
    USER08_LINKTYPE = 155,
    USER09_LINKTYPE = 156,
    USER10_LINKTYPE = 157,
    USER11_LINKTYPE = 158,
    USER12_LINKTYPE = 159,
    USER13_LINKTYPE = 160,
    USER14_LINKTYPE = 161,
    USER15_LINKTYPE = 162,
    IEEE802_11_AVS = 163,
    BACNET_MS_TP = 165,
    PPP_PPPD = 166,
    GPRS_LLC = 169,
    GPF_T = 170,
    GPF_F = 171,
    LINUX_LAPD = 177,
    BLUETOOTH_HCI_H4 = 187,
    USB_LINUX = 189,
    PPI = 192,
    IEEE802_15_4 = 195,
    SITA = 196,
    ERF = 197,
    BLUETOOTH_HCI_H4_WITH_PHDR = 201,
    AX25_KISS = 202,
    LAPD = 203,
    PPP_WITH_DIR = 204,
    C_HDLC_WITH_DIR = 205,
    FRELAY_WITH_DIR = 206,
    IPMB_LINUX = 209,
    IEEE802_15_4_NONASK_PHY = 215,
    USB_LINUX_MMAPPED = 220,
    FC_2 = 224,
    FC_2_WITH_FRAME_DELIMS = 225,
    IPNET = 226,
    CAN_SOCKETCAN = 227,
    IPV4 = 228,
    IPV6 = 229,
    IEEE802_15_4_NOFCS = 230,
    DBUS = 231,
    DVB_CI = 235,
    MUX27010 = 236,
    STANAG_5066_D_PDU = 237,
    NFLOG = 239,
    NETANALYZER = 240,
    NETANALYZER_TRANSPARENT = 241,
    IPOIB = 242,
    MPEG_2_TS = 243,
    NG40 = 244,
    NFC_LLCP = 245,
    INFINIBAND = 247,
    SCTP = 248,
    USBPCAP = 249,
    RTAC_SERIAL = 250,
    BLUETOOTH_LE_LL = 251,
    NETLINK = 253,
    BLUETOOTH_LINUX_MONITOR = 254,
    BLUETOOTH_BREDR_BB = 255,
    BLUETOOTH_LE_LL_WITH_PHDR = 256,
    PROFIBUS_DL = 257,
    PKTAP = 258,
    EPON = 259,
    IPMI_HPM_2 = 260,
    ZWAVE_R1_R2 = 261,
    ZWAVE_R3 = 262,
    WATTSTOPPER_DLM = 263,
    ISO_14443 = 264,
    RDS = 265,
    USB_DARWIN = 266,
}
impl From<Linktype> for u32 {
    fn from(val: Linktype) -> u32 {
        val as u32
    }
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_pcap_header() {
        // Rust docs are very fuzzy about the guarantees of repr(packed), so these tests verify
        // that the struct layouts are correct.
        assert_eq!(::std::mem::size_of::<PcapFileHeaderInFile>(), 24);
        assert_eq!(::std::mem::size_of::<PcapRecordHeader>(), 16);
    }
}
