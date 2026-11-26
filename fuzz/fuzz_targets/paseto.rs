//! PASETO v4.public: raw tokens through footer/peek/verify, and fuzzer-chosen messages and footers signed with a
//! fixed key, which must round-trip.
#![no_main]
use arbitrary::Arbitrary;
use islandmail_core::paseto;
use islandmail_fuzz_harness::world;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In<'a> {
    token: &'a str,
    message: &'a [u8],
    footer: &'a [u8],
    implicit: &'a [u8],
}

fuzz_target!(|i: In| {
    let key = world::alice();
    let _ = paseto::footer(i.token);
    let _ = paseto::peek(i.token);
    let _ = paseto::verify(i.token, &key.public(), i.footer, i.implicit);
    let t = paseto::sign(&key, i.message, i.footer, i.implicit);
    assert_eq!(paseto::verify(&t, &key.public(), i.footer, i.implicit).unwrap(), i.message);
    assert_eq!(paseto::peek(&t).unwrap(), i.message);
    assert_eq!(paseto::footer(&t).unwrap(), i.footer);
    assert!(paseto::verify(&t, &world::bob().public(), i.footer, i.implicit).is_err());
});
