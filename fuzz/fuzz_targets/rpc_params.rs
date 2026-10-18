#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| hashstash_fuzz::fuzz_one("rpc_params", data));
