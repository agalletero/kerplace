//! Decoder for the `aws-chunked` content encoding used by
//! `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` uploads.
//!
//! AWS CLI and `mc` frame streaming PUT/UploadPart bodies as a sequence of
//! `<hex-size>;chunk-signature=<sig>\r\n<data>\r\n` chunks terminated by a
//! zero-length chunk. This module strips that framing and yields the raw
//! object bytes. v0.1 does not verify per-chunk signatures (the request-level
//! SigV4 signature has already authenticated the caller).

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};

use crate::storage::BodyReader;

/// Wrap a reader of `aws-chunked` data in a decoder that yields the decoded
/// payload bytes.
///
/// # Parameters
/// - `reader`: a reader over the raw, chunk-framed request body.
///
/// # Returns
/// A [`BodyReader`] yielding the de-framed payload. Decoding runs on a spawned
/// task and back-pressures through an in-memory pipe.
pub fn decode_aws_chunked(reader: BodyReader) -> BodyReader {
    let (writer, read_half) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        if let Err(e) = pump(reader, writer).await {
            tracing::debug!("aws-chunked decode stopped: {e}");
        }
    });
    Box::pin(read_half)
}

/// Read chunk framing from `reader`, writing decoded bytes into `writer`.
///
/// # Parameters
/// - `reader`: the chunk-framed source.
/// - `writer`: the pipe half to which decoded bytes are written.
///
/// # Returns
/// `Ok(())` once the terminating zero-length chunk is reached, or an
/// [`std::io::Error`] on malformed framing or I/O failure.
async fn pump(reader: BodyReader, mut writer: DuplexStream) -> std::io::Result<()> {
    let mut buf = BufReader::new(reader);
    loop {
        let mut size_line = String::new();
        if buf.read_line(&mut size_line).await? == 0 {
            break; // EOF before a zero-length chunk; stop gracefully.
        }
        let trimmed = size_line.trim_end_matches(['\r', '\n']);
        // The size is the hex value before any `;chunk-signature=...` suffix.
        let size_hex = trimmed.split(';').next().unwrap_or("").trim();
        if size_hex.is_empty() {
            continue;
        }
        let size = u64::from_str_radix(size_hex, 16)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if size == 0 {
            break; // Final chunk.
        }
        let mut limited = (&mut buf).take(size);
        tokio::io::copy(&mut limited, &mut writer).await?;
        // Consume the trailing CRLF that follows each chunk's data.
        let mut crlf = [0u8; 2];
        let _ = buf.read_exact(&mut crlf).await;
    }
    writer.shutdown().await?;
    Ok(())
}
