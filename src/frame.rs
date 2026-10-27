//! Length-prefix framing used by every hbb_common `FramedStream` — hbbs TCP,
//! hbbr and RustDesk session streams all speak it.
//!
//! Wire format: a 1-4 byte little-endian header followed by the payload.
//! The low 2 bits of the first byte encode the header length
//! (0 => 1 byte .. 3 => 4 bytes); the remaining bits are the payload length.
//! Ported from hbb_common/src/bytes_codec.rs.

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME: usize = 0x3FFFFFFF;

/// Header bytes for a payload of `n` bytes.
pub fn header(n: usize) -> Vec<u8> {
    if n <= 0x3F {
        vec![(n << 2) as u8]
    } else if n <= 0x3FFF {
        (((n << 2) | 0x1) as u16).to_le_bytes().to_vec()
    } else if n <= 0x3FFFFF {
        let h = ((n << 2) | 0x2) as u32;
        [h as u8, (h >> 8) as u8, (h >> 16) as u8].to_vec()
    } else if n <= MAX_FRAME {
        (((n << 2) | 0x3) as u32).to_le_bytes().to_vec()
    } else {
        vec![] // caller must not send this much
    }
}

/// A complete frame ready for the wire.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = header(payload.len());
    out.extend_from_slice(payload);
    out
}

pub async fn send_frame<S: AsyncWrite + Unpin>(s: &mut S, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        bail!("frame too large: {}", payload.len());
    }
    s.write_all(&header(payload.len())).await?;
    s.write_all(payload).await?;
    Ok(())
}

/// Incremental deframer: feed it read bytes, pull out complete payloads.
pub struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Next complete payload, if the buffer holds one.
    pub fn next_payload(&mut self) -> Option<Vec<u8>> {
        if self.buf.is_empty() {
            return None;
        }
        let head_len = ((self.buf[0] & 0x3) + 1) as usize;
        if self.buf.len() < head_len {
            return None;
        }
        let mut n = 0usize;
        for i in 0..head_len {
            n |= (self.buf[i] as usize) << (8 * i);
        }
        n >>= 2;
        if self.buf.len() < head_len + n {
            return None;
        }
        let payload = self.buf[head_len..head_len + n].to_vec();
        self.buf.drain(..head_len + n);
        Some(payload)
    }

    /// Bytes left in the buffer after the last complete frame — belongs to a
    /// subsequent raw stream once a session switches to raw mode.
    pub fn take_remaining(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Read from the stream until one complete payload is available.
    pub async fn recv<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Result<Vec<u8>> {
        loop {
            if let Some(p) = self.next_payload() {
                return Ok(p);
            }
            let mut chunk = [0u8; 16384];
            let n = s.read(&mut chunk).await?;
            if n == 0 {
                bail!("peer closed the connection");
            }
            self.feed(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small() {
        let mut d = Deframer::new();
        d.feed(&frame(b"hello"));
        assert_eq!(d.next_payload().unwrap(), b"hello");
        assert!(d.next_payload().is_none());
    }

    #[test]
    fn roundtrip_medium() {
        let payload = vec![7u8; 300];
        let mut d = Deframer::new();
        d.feed(&frame(&payload));
        d.feed(&frame(b"next"));
        assert_eq!(d.next_payload().unwrap(), payload);
        assert_eq!(d.next_payload().unwrap(), b"next");
    }

    #[test]
    fn byte_at_a_time() {
        let wire = frame(&vec![9u8; 100]);
        let mut d = Deframer::new();
        for b in wire {
            d.feed(&[b]);
        }
        assert_eq!(d.next_payload().unwrap(), vec![9u8; 100]);
    }

    #[test]
    fn known_prefix() {
        // 68-byte payload frames as the 2-byte header 11 01 — the bytes the
        // stock client's TCP punch was observed to send.
        assert_eq!(header(68), vec![0x11, 0x01]);
        assert_eq!(header(144), vec![0x41, 0x02]);
        // The Hash message observed from a 1.4.5 peer: 18-byte payload.
        assert_eq!(header(18), vec![0x48]);
    }
}
