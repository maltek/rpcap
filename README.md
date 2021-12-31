RPCAP
=====

An all-Rust library for reading and writing PCAP files.
-------------------------------------------------------

[Full API Documentation](https://docs.rs/rpcap/)

```rust
use std::fs::File;
use std::io::{BufReader, BufWriter};
use rpcap::read::PcapReader;
use rpcap::write::{PcapWriter, WriteOptions};

// read a PCAP file
let infile = File::open("example.pcap").unwrap();
let reader = BufReader::new(infile);
let (file_opts, mut pcapr) = PcapReader::new(reader).unwrap();
println!("type of captured packets: {}", file_opts.linktype);
println!("maximum packet size: {}", file_opts.snaplen);

// create a new PCAP file
let outfile = File::create("copy.pcap").unwrap();
let writer = BufWriter::new(outfile);
let mut pcapw = PcapWriter::new(writer, file_opts).unwrap();

// copy all packets from example.pcap to copy.pcap
while let Some(packet) = pcapr.next().unwrap() {
    println!("packet at {:?} with size {} (cropped from {})",
        packet.time, packet.data.len(), packet.orig_len);
    pcapw.write(&packet).unwrap();
}
```

Please note that there is no support for the newer `pcapng` file format. If you need that, you might want to have a look at the [libpcap-wrapper for rust](https://crates.io/crates/pcap). The same applies if you need the advanced filtering options it has out of the box. To disect the packets from the pcap file, you could use the [pnet library](https://crates.io/crates/pnet). In the time between me writing and publishing this library, it looks like the [pcap-file](https://crates.io/crates/pcap-file) and [pcap-rs](https://crates.io/crates/pcap-rs) libraries have popped up, which seem to be doing a very similar thing as this library.

## Options

By default, timestamps are returned as `std::time::SystemTime`. With the optiona
`time` feature you can opt to get values as `time::Timespec` type from the `time`
crate (version `1.0`) instead:

```toml
[dependencies]
rpcap = { version = "1.0.0", features = ["time"] }
```



## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.


## Upgrading from Version 0.3

`PcapWriter::append` now requires an argument of type `Read + Write + Seek`.
This allows the library to ensure that the output format matches of written
packages matches the format specified in the file header. If this does not work
for your use case, you can use the new `PcapWriter::append_unchecked` function.
Be sure to only use it with files created with this library on the same
platform, or else the files might get corrupted.

`PcapReader::new` now returns a tuple of information about the file header and a
faux-iterator. If you do not need the first item in the tuple, you can do
something like `let (_, reader) = PcapReader::new()`.

`WriteOptions` is now called `FileOptions`, and has two additional fields. As a
result, all possible variants of PCAP (v1) files can be created now. Due to the
previous changes, it is now much less likely you'd have to manually create
instances of this struct. If you do and are upgrading from an old release, set
`high_res_timestamps` to `true` and `non_native_byte_order` to `false` to get
the old behavior back.
