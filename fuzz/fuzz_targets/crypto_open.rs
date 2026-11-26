//! Raw ciphertext, ephemeral key and wrap slots through content_key, open, decrypt and the blob cipher; padding.
#![no_main]
use arbitrary::Arbitrary;
use islandmail_core::crypto::{self, Wrapped};
use islandmail_fuzz_harness::world;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In {
    ct: Vec<u8>,
    ad: Vec<u8>,
    epk: [u8; 32],
    wraps: Vec<([u8; 16], Vec<u8>)>,
    blob_key: [u8; 32],
    chunk_pow: u8,
}

fuzz_target!(|i: In| {
    let me = world::node_a();
    let wraps: Vec<Wrapped> = i.wraps.iter().take(8).map(|(t, k)| Wrapped { tag: *t, k: k.clone() }).collect();
    let _ = crypto::open(&i.ct, &i.ad, &i.epk, &wraps, &me);
    let _ = crypto::content_key(&i.epk, &wraps, &me);
    let _ = crypto::decrypt_with(&i.ct, &i.ad, &i.blob_key);
    let _ = crypto::open_blob(&i.ct, &i.blob_key);
    let _ = crypto::unpad(&i.ct);
    let chunk = 1usize << (10 + i.chunk_pow % 11);
    if i.ct.len() < 1 << 16 {
        let p = crypto::pad(&i.ct, chunk).unwrap();
        assert_eq!(p.len(), crypto::padded_len(i.ct.len(), chunk));
        assert!(crypto::is_padded_len(p.len(), chunk));
        assert_eq!(crypto::unpad(&p).unwrap(), i.ct);
        let (blob, key) = crypto::seal_blob(&i.ct).unwrap();
        assert_eq!(blob.len(), crypto::blob_len(i.ct.len()));
        assert_eq!(crypto::open_blob(&blob, &key).unwrap(), i.ct);
    }
    // A sealed message opens for each target and no one else.
    if !i.ad.is_empty() && i.ad.len() < 512 {
        let targets = crypto::identity_targets(&[me.public(), world::bob().public()]).unwrap();
        let s = crypto::seal(&i.ad, b"ad", &targets).unwrap();
        assert!(s.keys.len().is_power_of_two() && s.keys.len() >= crypto::MIN_SLOTS);
        assert_eq!(crypto::open(&s.ciphertext, b"ad", &s.epk, &s.keys, &me).unwrap().unwrap(), i.ad);
        assert!(crypto::open(&s.ciphertext, b"ad", &s.epk, &s.keys, &world::alice()).unwrap().is_none());
    }
});
