#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rpcap;

fuzz_target!(|data: &[u8]| {
    rpcap::fuzz::fuzz(data);
});
