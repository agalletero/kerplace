//! Phase-0 microbenchmarks — at-rest crypto inner loops at KerPlace's real sizes.
//!
//! Measures the AEAD chunk path (the `KP_ENCRYPT` cost) and the BLAKE3 shard
//! checksum, isolated from I/O, to establish CPU-per-GB ceilings (PERFORMANCE.md
//! §2). The AES-GCM group is the **P1.5 A/B**: RustCrypto `aes-gcm` (what KerPlace
//! uses today, AES-NI single-block) vs `ring` (already a dependency).
//!
//! Run: `cargo bench --bench crypto`
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

/// KerPlace's AEAD chunk size (`CHUNK_SIZE` in src/crypto/mod.rs).
const CHUNK: usize = 64 * 1024;
/// A representative erasure shard (≈ a 1 MiB block split K=2).
const SHARD: usize = 512 * 1024;

fn aead(c: &mut Criterion) {
    let data = vec![0x5Au8; CHUNK];
    let key = [7u8; 32];
    let nonce = [0u8; 12];

    let mut g = c.benchmark_group("aead_64k");
    g.throughput(Throughput::Bytes(CHUNK as u64));

    // --- RustCrypto aes-gcm 0.10 (current path) ---
    {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        g.bench_function("rustcrypto_seal", |b| {
            b.iter(|| black_box(cipher.encrypt(Nonce::from_slice(&nonce), data.as_slice()).unwrap()))
        });
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), data.as_slice()).unwrap();
        g.bench_function("rustcrypto_open", |b| {
            b.iter(|| black_box(cipher.decrypt(Nonce::from_slice(&nonce), ct.as_slice()).unwrap()))
        });
    }

    // --- ring (P1.5 candidate; already compiled in via rustls) ---
    {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
        let aead_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).unwrap());
        g.bench_function("ring_seal", |b| {
            b.iter(|| {
                let mut buf = data.clone();
                aead_key
                    .seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::empty(),
                        &mut buf,
                    )
                    .unwrap();
                black_box(buf);
            })
        });
        let mut sealed = data.clone();
        aead_key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut sealed)
            .unwrap();
        g.bench_function("ring_open", |b| {
            b.iter(|| {
                let mut buf = sealed.clone();
                let pt = aead_key
                    .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
                    .unwrap();
                black_box(pt.len());
            })
        });
    }
    g.finish();
}

fn hashing(c: &mut Criterion) {
    let shard = vec![0x5Au8; SHARD];
    let mut g = c.benchmark_group("blake3_shard_512k");
    g.throughput(Throughput::Bytes(SHARD as u64));
    // The raw digest (what we'd compare if F11/P1.5 stores bytes).
    g.bench_function("hash", |b| b.iter(|| black_box(blake3::hash(&shard))));
    // The current path: digest + hex String allocation (F11) — the overhead to remove.
    g.bench_function("hash_to_hex_string", |b| {
        b.iter(|| black_box(blake3::hash(&shard).to_hex().to_string()))
    });
    g.finish();
}

/// Object-level hashing over 1 MiB: **MD5 (the S3 ETag)** vs BLAKE3. The flamegraph
/// showed `md5::compress::soft` as the #1 on-CPU function (~32%) of a PUT — MD5 runs
/// the no-SIMD soft path and is inherently sequential, so it's the slowest per-byte
/// hash and a top write-path compute cost. This quantifies it.
fn object_hash(c: &mut Criterion) {
    use md5::{Digest, Md5};
    let obj = vec![0x5Au8; 1024 * 1024];
    let mut g = c.benchmark_group("object_hash_1mib");
    g.throughput(Throughput::Bytes(1024 * 1024));
    g.bench_function("md5_etag", |b| {
        b.iter(|| {
            let mut h = Md5::new();
            h.update(&obj);
            black_box(h.finalize())
        })
    });
    g.bench_function("blake3", |b| b.iter(|| black_box(blake3::hash(&obj))));
    g.finish();
}

criterion_group!(benches, aead, hashing, object_hash);
criterion_main!(benches);
