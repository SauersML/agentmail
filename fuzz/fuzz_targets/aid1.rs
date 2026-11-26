//! Home identity tokens (`aid1.<payload>.<sig>`) and proofs of possession: raw tokens, and fuzzer-chosen payloads
//! signed by the pinned issuer key.
#![no_main]
use arbitrary::Arbitrary;
use islandmail_core::aid1;
use islandmail_core::b64u;
use islandmail_fuzz_harness::world;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In<'a> {
    token: &'a str,
    payload: &'a [u8],
    kg: Option<u64>,
    ts: &'a str,
    jti: &'a str,
    sig: &'a str,
}

fuzz_target!(|i: In| {
    let issuer = world::seed(30);
    let pk = issuer.public();
    let ex = aid1::Expect { key: &pk, iss: "id.test", aud: "islandmail:test", kg: i.kg };
    let now = 1_700_000_000_000;
    let _ = aid1::verify(i.token, &ex, now);
    let seg = b64u(i.payload);
    let signed = format!("aid1.{seg}");
    let tok = format!("{signed}.{}", b64u(&issuer.sign(signed.as_bytes())));
    if let Ok(p) = aid1::verify(&tok, &ex, now) {
        assert!(p.exp > now as f64 / 1000.0 && !p.sub.is_empty() && !p.name.is_empty());
    }
    let _ = aid1::valid_jti(i.jti);
    let _ = aid1::check_presentation(&world::alice().public(), "id.test", "islandmail:test", i.ts, i.jti, &tok, i.sig);
});
