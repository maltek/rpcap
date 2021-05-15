#[macro_use]
extern crate afl;
extern crate rpcap;

fn main() {
    fuzz!(|data: &[u8]| {
        rpcap::fuzz::fuzz(data);
    });
}
