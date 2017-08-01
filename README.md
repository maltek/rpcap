RPCAP
=====

An all-Rust library for reading and writing PCAP files.
-------------------------------------------------------

```rust
// read a PCAP file
let infile = File::open("example.pcap").unwrap();
let reader = BufReader::new(infile);
let mut pcapr = PcapReader::new(reader).unwrap();
println!("linktype: {}", pcapr.get_linktype());
println!("snaplen: {}", pcapr.get_snaplen());

// create a new PCAP file
let outfile = File::create("copy.pcap").unwrap();
let writer = BufWriter::new(outfile);
let mut pcapw = PcapWriter::new(writer, WriteOptions {
    snaplen: pcapr.get_linktype(),
    linktype: pcapr.get_snaplen(),
}).unwrap();

// copy all packets from example.pcap to copy.pcap
while let Some(packet) = pcapr.next().unwrap() {
    println!("packet at {} with size {} (cropped to {})", 
        packet.time, packet.data.len(), packet.orig_len);
    pcapw.write(&packet).unwrap();
}
```

Please note that there is no support for the newer `pcapng` file format. If you need that, you might want to have a look at the [libpcap-wrapper for rust](https://crates.io/crates/pcap). The same applies if you need the advanced filtering options it has out of the box. To disect the packets from the pcap file, you could use the [pnet library](https://crates.io/crates/pnet). In the time between me writing and publishing this library, it looks like the [pcap-file](https://crates.io/crates/pcap-file) and [pcap-rs](https://crates.io/crates/pcap-rs) libraries have popped up, which seem to be doing a very similar thing as this library.


## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
