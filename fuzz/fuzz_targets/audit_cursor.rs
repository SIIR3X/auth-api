#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| auth_api::fuzzing::audit_cursor(data));
