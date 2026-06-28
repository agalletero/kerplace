//! Phase-0 microbenchmarks — Reed-Solomon encode + reconstruct at KerPlace's
//! geometry, **A/B**: the current scalar `reed-solomon-erasure` (`simd-accel` OFF,
//! finding F1) vs `reed-solomon-simd` (the P1.2 candidate, pure-Rust runtime SIMD).
//!
//! Mirrors `Codec::encode_block` / `reconstruct_block` (src/erasure/codec.rs).
//! Run: `cargo bench --bench erasure`
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// KerPlace's default erasure block size (`KP_ERASURE_BLOCK`).
const BLOCK: usize = 1024 * 1024;
/// Today's default (2+2) and a MinIO-class wide set (12+4).
const GEOMETRIES: &[(usize, usize)] = &[(2, 2), (12, 4)];

/// reed-solomon-simd needs even shard lengths; round up.
fn even(n: usize) -> usize {
    if n % 2 == 0 { n } else { n + 1 }
}

/// K data shards of `slen` bytes, deterministically filled.
fn make_data(k: usize, slen: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| vec![(i as u8).wrapping_mul(31).wrapping_add(1); slen])
        .collect()
}

fn encode(c: &mut Criterion) {
    let mut g = c.benchmark_group("rs_encode_1mib");
    g.throughput(Throughput::Bytes(BLOCK as u64));
    for &(k, m) in GEOMETRIES {
        let slen = even(BLOCK.div_ceil(k));
        let geom = format!("{k}+{m}");

        // --- scalar (current) ---
        let rs = ReedSolomon::new(k, m).unwrap();
        g.bench_with_input(BenchmarkId::new("scalar", &geom), &(), |b, _| {
            b.iter_batched(
                || {
                    let mut s = make_data(k, slen);
                    s.extend((0..m).map(|_| vec![0u8; slen]));
                    s
                },
                |mut s| {
                    rs.encode(&mut s).unwrap();
                    black_box(s);
                },
                BatchSize::LargeInput,
            )
        });

        // --- simd (P1.2 candidate) ---
        g.bench_with_input(BenchmarkId::new("simd", &geom), &(), |b, _| {
            b.iter_batched(
                || make_data(k, slen),
                |orig| {
                    let recovery = reed_solomon_simd::encode(k, m, &orig).unwrap();
                    black_box(recovery);
                },
                BatchSize::LargeInput,
            )
        });
    }
    g.finish();
}

fn reconstruct(c: &mut Criterion) {
    let mut g = c.benchmark_group("rs_reconstruct_1mib");
    g.throughput(Throughput::Bytes(BLOCK as u64));
    for &(k, m) in GEOMETRIES {
        let slen = even(BLOCK.div_ceil(k));
        let geom = format!("{k}+{m}_lose_{m}_data");

        // --- scalar (current) ---
        let rs = ReedSolomon::new(k, m).unwrap();
        let mut full = make_data(k, slen);
        full.extend((0..m).map(|_| vec![0u8; slen]));
        rs.encode(&mut full).unwrap();
        g.bench_with_input(BenchmarkId::new("scalar", &geom), &(), |b, _| {
            b.iter_batched(
                || {
                    let mut opt: Vec<Option<Vec<u8>>> = full.iter().cloned().map(Some).collect();
                    for slot in opt.iter_mut().take(m) {
                        *slot = None;
                    }
                    opt
                },
                |mut opt| {
                    rs.reconstruct(&mut opt).unwrap();
                    black_box(opt);
                },
                BatchSize::LargeInput,
            )
        });

        // --- simd (P1.2 candidate) ---
        let orig = make_data(k, slen);
        let recovery = reed_solomon_simd::encode(k, m, &orig).unwrap();
        g.bench_with_input(BenchmarkId::new("simd", &geom), &(), |b, _| {
            b.iter(|| {
                // Lose the first M originals; recover from the surviving (K-M)
                // originals + the M recovery shards.
                let surviving = (m..k).map(|i| (i, orig[i].as_slice()));
                let recov = (0..m).map(|i| (i, recovery[i].as_slice()));
                let restored = reed_solomon_simd::decode(k, m, surviving, recov).unwrap();
                black_box(restored);
            })
        });
    }
    g.finish();
}

criterion_group!(benches, encode, reconstruct);
criterion_main!(benches);
