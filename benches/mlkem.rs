//! Phase-0 microbenchmarks — ML-KEM-1024 (the `file` provider's PQC envelope).
//!
//! `encapsulate` runs per PUT; on every GET the current code rebuilds the
//! decapsulation key **from the seed** before decapsulating (finding F8). This
//! bench isolates that rebuild so the P1.5/QW2 win (cache the decap key) is
//! quantified: compare `decapsulate_key_cached` vs `decapsulate_current_from_seed`.
//!
//! These are per-object (not per-byte) costs. Run: `cargo bench --bench mlkem`
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ml_kem::{Decapsulate, DecapsulationKey, Encapsulate, Kem, KeyExport, MlKem1024};

fn mlkem(c: &mut Criterion) {
    let (dk, ek) = MlKem1024::generate_keypair();
    let seed_bytes: [u8; 64] = dk.to_bytes().as_slice().try_into().unwrap();
    let (ct, _ss) = ek.encapsulate();

    let mut g = c.benchmark_group("mlkem1024");

    // Per-PUT: encapsulate (produces the wrapped DEK + shared secret).
    g.bench_function("encapsulate", |b| b.iter(|| black_box(ek.encapsulate())));

    // The F8 cost on its own: rebuild the decap key from the 64-byte seed.
    g.bench_function("from_seed_rebuild_decap_key", |b| {
        b.iter(|| {
            let seed: ml_kem::Seed = seed_bytes.as_ref().try_into().unwrap();
            black_box(DecapsulationKey::<MlKem1024>::from_seed(seed))
        })
    });

    // QW2 target: decapsulate with the key already in hand.
    g.bench_function("decapsulate_key_cached", |b| {
        b.iter(|| black_box(dk.decapsulate(&ct)))
    });

    // What KerPlace does on every GET today: from_seed THEN decapsulate.
    g.bench_function("decapsulate_current_from_seed", |b| {
        b.iter(|| {
            let seed: ml_kem::Seed = seed_bytes.as_ref().try_into().unwrap();
            let dk2 = DecapsulationKey::<MlKem1024>::from_seed(seed);
            black_box(dk2.decapsulate(&ct))
        })
    });

    g.finish();
}

criterion_group!(benches, mlkem);
criterion_main!(benches);
