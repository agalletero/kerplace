//! Distributed cluster support (Phase 4): the internal storage RPC that lets an
//! [`ErasureStore`](crate::erasure::store::ErasureStore) shard slot live on
//! another node. See `docs/DISTRIBUTED_DESIGN.md`.
//!
//! - [`server`] runs a node in "drive mode": it exposes a [`LocalDrive`] over an
//!   authenticated internal HTTP API (`/_kerplace/drive/v1/*`), bound to the
//!   overlay-mesh interface.
//! - [`remote`] is the client side: [`RemoteDrive`] implements the
//!   [`Drive`](crate::erasure::drive::Drive) trait by calling that API, so the
//!   store treats a remote node exactly like a local directory.
//!
//! The wire format is plain HTTP + JSON metadata; payloads (`part.1`, `xl.meta`)
//! are raw bytes. Every request carries `Authorization: Bearer <cluster secret>`.

use serde::{Deserialize, Serialize};

pub mod lock;
pub mod mtls;
pub mod remote;
pub mod server;

/// Path prefix for every drive RPC endpoint.
pub const DRIVE_API: &str = "/_kerplace/drive/v1";

/// Wire form of [`DriveStat`](crate::erasure::drive::DriveStat).
#[derive(Debug, Serialize, Deserialize)]
pub struct StatDto {
    /// File length in bytes.
    pub len: u64,
    /// Whether the path is a directory.
    pub is_dir: bool,
}

/// Wire form of one [`DirEntry`](crate::erasure::drive::DirEntry).
#[derive(Debug, Serialize, Deserialize)]
pub struct DirEntryDto {
    /// Final path component.
    pub name: String,
    /// Whether the child is a directory.
    pub is_dir: bool,
    /// Creation time as a Unix timestamp (seconds), when known.
    pub created_unix: Option<i64>,
}

/// Wire form of one [`WalkEntry`](crate::erasure::drive::WalkEntry); `rel` is a
/// forward-slash path relative to the walk base.
#[derive(Debug, Serialize, Deserialize)]
pub struct WalkEntryDto {
    /// Forward-slash path relative to the walk base.
    pub rel: String,
    /// Whether this entry is a regular file.
    pub is_file: bool,
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::cluster::remote::RemoteDrive;
    use crate::cluster::server::drive_router;
    use crate::erasure::drive::{Drive, LocalDrive};

    /// Spawn an in-process drive server over a temp dir; return its base URL.
    async fn spawn_drive(secret: &str) -> (String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let drive = Arc::new(LocalDrive::new(dir.path().to_path_buf()));
        let app = drive_router(drive, secret.to_string());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), dir)
    }

    /// `RemoteDrive` exercises every `Drive` op against a real drive server,
    /// including the streaming `create`→`shutdown` PUT and bearer auth.
    #[tokio::test]
    async fn remote_drive_round_trips_all_ops() {
        let (base, _dir) = spawn_drive("s3cr3t").await;
        let rd = RemoteDrive::new(base, "s3cr3t");
        assert!(rd.online().await);

        rd.create_dir_all(Path::new("buck/obj")).await.unwrap();
        rd.write(Path::new("buck/obj/part.1"), b"hello world").await.unwrap();
        assert_eq!(rd.read(Path::new("buck/obj/part.1")).await.unwrap(), b"hello world");
        assert_eq!(rd.read_at(Path::new("buck/obj/part.1"), 6, 5).await.unwrap(), b"world");

        let s = rd.stat(Path::new("buck/obj/part.1")).await.unwrap();
        assert_eq!(s.len, 11);
        assert!(!s.is_dir);

        let w = rd.walk(Path::new("buck")).await.unwrap();
        assert!(w.iter().any(|e| e.is_file && e.rel == Path::new("obj/part.1")));
        let entries = rd.read_dir(Path::new("buck/obj")).await.unwrap();
        assert!(entries.iter().any(|e| e.name == "part.1" && !e.is_dir));

        rd.rename(Path::new("buck/obj/part.1"), Path::new("buck/obj/part.2")).await.unwrap();
        assert!(rd.read(Path::new("buck/obj/part.1")).await.is_err());
        assert_eq!(rd.read(Path::new("buck/obj/part.2")).await.unwrap(), b"hello world");

        // Streaming writer: buffered writes flushed as one PUT on shutdown.
        let mut sw = rd.create(Path::new("buck/obj/streamed")).await.unwrap();
        sw.write_all(b"abc").await.unwrap();
        sw.write_all(b"def").await.unwrap();
        sw.shutdown().await.unwrap();
        assert_eq!(rd.read(Path::new("buck/obj/streamed")).await.unwrap(), b"abcdef");

        rd.remove_file(Path::new("buck/obj/part.2")).await.unwrap();
        assert!(rd.read(Path::new("buck/obj/part.2")).await.is_err());
        assert!(rd.read(Path::new("nope")).await.is_err());
        assert!(rd.stat(Path::new("nope")).await.is_err());

        // Wrong secret ⇒ unauthorized.
        let bad = RemoteDrive::new(rd.id(), "wrong");
        assert!(!bad.online().await);
        assert!(bad.read(Path::new("buck/obj/streamed")).await.is_err());
    }

    /// An `ErasureStore` with a mix of local + remote drives round-trips an
    /// object and reconstructs it after losing two shards — proving the remote
    /// shard is real and used during reconstruction.
    #[tokio::test]
    async fn erasure_over_remote_drive_is_durable() {
        use crate::crypto::{CryptoContext, MasterKey};
        use crate::erasure::store::ErasureStore;
        use crate::storage::ObjectStore;

        let secret = "clustersecret";
        let (base, _rdir) = spawn_drive(secret).await;
        let locals: Vec<tempfile::TempDir> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
        let mut drives: Vec<Arc<dyn Drive>> = Vec::new();
        for l in &locals {
            drives.push(Arc::new(LocalDrive::new(l.path().to_path_buf())));
        }
        drives.push(Arc::new(RemoteDrive::new(base, secret))); // shard slot 3 = remote node

        let store = ErasureStore::with_drives(
            drives,
            CryptoContext::new_aes(MasterKey::generate()),
            false,
            2, // parity 2 of 4 ⇒ K=2
            4096,
        )
        .unwrap();
        store.create_bucket("buck").await.unwrap();

        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        store
            .put_object(
                "buck",
                "obj",
                Box::pin(std::io::Cursor::new(data.clone())),
                "application/octet-stream".into(),
                Default::default(),
                false,
            )
            .await
            .unwrap();

        let (_, mut body) = store.get_object("buck", "obj").await.unwrap();
        let mut got = Vec::new();
        body.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data, "read back through the cluster (incl. the remote shard)");

        // Lose two local shards entirely → must reconstruct from the surviving
        // local shard + the remote one (exactly K=2 of 4).
        for l in locals.iter().take(2) {
            std::fs::remove_dir_all(l.path().join("buck/obj")).unwrap();
        }
        let (_, mut body) = store.get_object("buck", "obj").await.unwrap();
        let mut got2 = Vec::new();
        body.read_to_end(&mut got2).await.unwrap();
        assert_eq!(got2, data, "reconstructs from 1 local + the remote shard");
    }

    /// Streaming: a 500 KB object (well past the 64 KB duplex buffer) round-trips
    /// through `create`→`shutdown` and `open` without buffering the whole file —
    /// exercising backpressure and the server's stream-to-disk path. `read_at`
    /// still serves a positioned slice of the streamed file.
    #[tokio::test]
    async fn remote_drive_streams_large_file() {
        let (base, _dir) = spawn_drive("s3cr3t").await;
        let rd = RemoteDrive::new(base, "s3cr3t");
        rd.create_dir_all(Path::new("big")).await.unwrap();

        let data: Vec<u8> = (0..500_000u32).map(|i| (i % 251) as u8).collect();
        let mut w = rd.create(Path::new("big/blob")).await.unwrap();
        for chunk in data.chunks(40_000) {
            w.write_all(chunk).await.unwrap();
        }
        w.shutdown().await.unwrap();

        let mut r = rd.open(Path::new("big/blob")).await.unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data, "500 KB streamed write+read round-trips");
        assert_eq!(
            rd.read_at(Path::new("big/blob"), 100_000, 5).await.unwrap(),
            &data[100_000..100_005],
            "positioned read on a streamed file"
        );
    }
}
