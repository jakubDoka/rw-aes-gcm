#[doc = include_str!("../README.md")]
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::rand_core::RngCore as _;
use aes_gcm::aead::{AeadMutInPlace, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::convert::TryInto;
use std::io::{self, Read, Seek, SeekFrom, Write};

const DEFAULT_BUF_CAP: usize = 64 * 1024;
const NONCE_SIZE: usize = 12;
const LEN_SIZE: usize = 8;
const TAG_SIZE: usize = 16;

pub struct Config {
    pub buf_cap: usize,
    pub asoc_data: &'static [u8],
}

impl Default for Config {
    fn default() -> Self {
        Config {
            buf_cap: DEFAULT_BUF_CAP,
            asoc_data: b"default",
        }
    }
}

/// Expects W to yield plaintext end outputs ciphertext
pub struct EncryptWriter<W: Write> {
    inner: W,
    cipher: Aes256Gcm,
    buf: Vec<u8>,
    asoc_data: &'static [u8],
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(inner: W, key: [u8; 32]) -> Self {
        Self::new_with_config(inner, key, Config::default())
    }

    pub fn new_with_config(inner: W, key: [u8; 32], cfg: Config) -> Self {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key));
        Self {
            inner,
            cipher,
            buf: Vec::with_capacity(cfg.buf_cap),
            asoc_data: cfg.asoc_data,
        }
    }

    pub fn flush_frame(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .ok()
            .ok_or(io::ErrorKind::Other)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, self.asoc_data, &mut self.buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encrypt error: {}", e)))?;

        let len = (self.buf.len() as u64 + TAG_SIZE as u64).to_be_bytes();
        self.inner.write_all(&len)?;
        self.inner.write_all(&nonce_bytes)?;
        self.inner.write_all(&self.buf)?;
        self.inner.write_all(&tag)?;
        self.inner.flush()?;

        self.buf.clear();
        Ok(())
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let to_write = data.len();

        while !data.is_empty() {
            let cap = self.buf.capacity();

            let can_write = data.len().min(cap - self.buf.len());
            self.buf.extend_from_slice(&data[..can_write]);
            data = &data[can_write..];

            debug_assert!(self.buf.len() <= cap);

            if self.buf.len() == cap {
                self.flush_frame()?;
            }
        }

        Ok(to_write)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_frame()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for EncryptWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush_frame();
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EncryptedFrame {
    pub start: u64,
    pub len: u64,
    pub plain_pos: u64,
}

struct SeekIndex {
    pub frames: Vec<EncryptedFrame>,
    pub current_frame: Option<usize>,
    pub file_size: u64,
}

impl SeekIndex {
    pub fn new(reader: &mut (impl Read + Seek)) -> io::Result<Self> {
        reader.seek(SeekFrom::Start(0))?;

        let mut frames = Vec::new();
        let mut offset: u64 = 0;
        let mut plain_pos: u64 = 0;

        loop {
            let frame_start = offset;
            let plain_start = plain_pos;

            let mut len_buf = [0u8; 8];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => return Err(e),
            }

            offset += 8;

            let cipher_len = u64::from_be_bytes(len_buf);

            if cipher_len == 0 {
                break;
            }

            let total_frame_len = 8 + NONCE_SIZE as u64 + cipher_len;

            reader.seek(SeekFrom::Current((NONCE_SIZE as u64 + cipher_len) as i64))?;
            offset += NONCE_SIZE as u64 + cipher_len;
            plain_pos += cipher_len - TAG_SIZE as u64;

            frames.push(EncryptedFrame {
                start: frame_start,
                len: total_frame_len,
                plain_pos: plain_start,
            });
        }

        reader.seek(SeekFrom::Start(0))?;

        Ok(Self {
            frames,
            current_frame: None,
            file_size: plain_pos,
        })
    }
}

/// Expects R to yield ciphertext encoded with EncryptWriter
pub struct DecryptReader<R: Read> {
    inner: R,
    cipher: Aes256Gcm,
    seek_index: Option<SeekIndex>,
    plain_buf: Vec<u8>,
    plain_pos: usize,
    asoc_data: &'static [u8],
}

impl<R: Read + Seek> Seek for DecryptReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let index = match self.seek_index {
            Some(ref mut index) => index,
            None => {
                let index = SeekIndex::new(&mut self.inner)?;
                self.seek_index.insert(index)
            }
        };

        let pos = match pos {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(pos) => (index.file_size as i64 + pos) as u64,
            SeekFrom::Current(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SeekFrom::Current not supported",
                ));
            }
        };

        if pos > index.file_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seeking past end of file",
            ));
        }

        let frame_idx = match index.frames.binary_search_by(|f| f.plain_pos.cmp(&pos)) {
            Ok(frame) => frame,
            Err(frame) => frame - 1,
        };

        let frame = index.frames[frame_idx];

        if Some(frame_idx) != index.current_frame {
            index.current_frame = Some(frame_idx);
            self.inner.seek(SeekFrom::Start(frame.start))?;
            self.fill_next_frame(true)?;
        } else {
            self.inner.seek(SeekFrom::Start(frame.start + frame.len))?;
        }

        self.plain_pos = (pos - frame.plain_pos) as usize;

        Ok(pos)
    }
}

impl<R: Read> DecryptReader<R> {
    pub fn new(inner: R, key: [u8; 32]) -> Self {
        Self::new_with_config(inner, key, Default::default())
    }

    pub fn new_with_config(inner: R, key: [u8; 32], cfg: Config) -> Self {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key));
        Self {
            inner,
            cipher,
            seek_index: None,
            plain_buf: Vec::new(),
            plain_pos: 0,
            asoc_data: cfg.asoc_data,
        }
    }

    fn fill_next_frame(&mut self, seeking: bool) -> io::Result<bool> {
        if !seeking {
            // NOTE: advance the seek if given opportunity (not doing this is actually incorrect)
            if let Some(ref mut index) = self.seek_index {
                if let Some(ref mut frame) = index.current_frame {
                    *frame += 1;
                }
            }
        }

        let mut lenb = [0u8; LEN_SIZE];
        match self.inner.read_exact(&mut lenb) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
        let clen = u64::from_be_bytes(lenb);
        if clen == 0 {
            return Ok(false);
        }
        let clen: usize = clen
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length too large"))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        self.inner.read_exact(&mut nonce_bytes)?;

        self.plain_buf.clear();
        self.plain_buf.resize(clen, 0);

        self.inner.read_exact(&mut self.plain_buf)?;

        let Some((ciphertext, tag)) = self.plain_buf.split_at_mut_checked(clen - TAG_SIZE) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too small",
            ));
        };

        let nonce = Nonce::from_slice(&nonce_bytes);
        self.cipher
            .decrypt_in_place_detached(
                nonce,
                self.asoc_data,
                ciphertext,
                GenericArray::from_slice(tag),
            )
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("decrypt error: {}", e))
            })?;

        self.plain_buf.truncate(clen - TAG_SIZE);
        self.plain_pos = 0;

        Ok(true)
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.plain_pos < self.plain_buf.len() {
            let available = &self.plain_buf[self.plain_pos..];
            let n = std::cmp::min(available.len(), out.len());
            out[..n].copy_from_slice(&available[..n]);
            self.plain_pos += n;
            return Ok(n);
        }

        match self.fill_next_frame(false)? {
            true => self.read(out),
            false => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        io::{Cursor, Read, Write},
        usize,
    };

    #[test]
    fn streamed_chipher_sanity() -> io::Result<()> {
        let key: [u8; 32] = [0x11; 32];

        let mut sink = Vec::new();
        let mut enc = EncryptWriter::new(&mut sink, key);
        writeln!(enc, "hello world!")?;
        enc.flush()?;
        writeln!(enc, "another line")?;

        drop(enc);

        let mut dec = DecryptReader::new(Cursor::new(sink), key);
        let mut out = String::new();
        dec.read_to_string(&mut out)?;

        assert_eq!(out, "hello world!\nanother line\n");

        Ok(())
    }

    #[test]
    fn streamed_chipher_fuzz() -> io::Result<()> {
        for _ in 0..100 {
            let key: [u8; 32] = rand::random();

            let text_len: usize = rand::random_range(0..1024 * 128);
            let message = rand::random_iter::<u8>().take(text_len).collect::<Vec<_>>();

            let mut cursor = message.as_slice();
            let mut sink = Vec::new();
            let mut enc = EncryptWriter::new(&mut sink, key);

            while !cursor.is_empty() {
                let chunk = cursor
                    .split_off(..rand::random_range(..=cursor.len()))
                    .expect("split_off");

                enc.write_all(&chunk)?;
            }

            drop(enc);

            let mut dec = DecryptReader::new(Cursor::new(sink), key);
            let mut out = Vec::new();

            loop {
                let max_read = rand::random_range(0..1024 * 128);
                let mut buf = vec![0u8; max_read];
                match dec.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                    Err(e) => panic!("read error: {e}"),
                }
            }

            assert_eq!(out, message);
        }
        Ok(())
    }

    #[test]
    fn streamed_chipher_seek_sanity() -> io::Result<()> {
        const MESSAGE_SIZE: usize = 1024 * 1024;
        const CHUNK_SIZE: usize = 1024 * 128;

        let mut message = vec![0u8; MESSAGE_SIZE];
        for (i, chunk) in message.chunks_mut(CHUNK_SIZE).enumerate() {
            chunk.fill(i as u8);
        }

        let key = [0x11; 32];

        let mut sink = Vec::new();
        let mut enc = EncryptWriter::new(&mut sink, key);
        for chunk in message.chunks(CHUNK_SIZE * 2) {
            enc.write_all(chunk)?;
        }
        drop(enc);

        let mut dec = DecryptReader::new(Cursor::new(sink), key);

        let mut reconstructed = vec![0u8; MESSAGE_SIZE];
        for (i, chunk) in reconstructed.chunks_mut(CHUNK_SIZE).enumerate().rev() {
            let offset = i * CHUNK_SIZE;
            dec.seek(SeekFrom::Start(offset as _))?;
            dec.read_exact(chunk)?;
        }

        assert_eq!(reconstructed, message);

        Ok(())
    }

    #[test]
    fn streamed_chipher_seek_fuzz() -> io::Result<()> {
        const MESSAGE_SIZE: usize = 1024 * 1024;

        let message = rand::random_iter::<u8>()
            .take(MESSAGE_SIZE)
            .collect::<Vec<_>>();

        let key = [0x11; 32];

        let mut sink = Vec::new();
        let mut enc = EncryptWriter::new(&mut sink, key);
        for chunk in message.chunks(8 * 1024) {
            enc.write_all(chunk)?;
        }
        drop(enc);

        let mut dec = DecryptReader::new(Cursor::new(sink), key);

        for _ in 0..100 {
            let offset = rand::random_range(0..=MESSAGE_SIZE);
            let len = rand::random_range(0..=MESSAGE_SIZE - offset);

            dec.seek(SeekFrom::Start(offset as _))?;
            let mut reconstructed = vec![0u8; len];
            dec.read_exact(&mut reconstructed)?;

            assert_eq!(reconstructed, &message[offset..offset + len]);
        }

        Ok(())
    }

    #[test]
    fn streamed_chipher_seek_end_sanity() -> io::Result<()> {
        const MESSAGE_SIZE: usize = 1024 * 1024;

        let message = rand::random_iter::<u8>()
            .take(MESSAGE_SIZE)
            .collect::<Vec<_>>();

        let key = [0x11; 32];

        let mut sink = Vec::new();
        let mut enc = EncryptWriter::new(&mut sink, key);
        enc.write_all(&message)?;
        drop(enc);

        let mut dec = DecryptReader::new(Cursor::new(sink), key);

        let res = dec.seek(SeekFrom::End(0))?;
        assert_eq!(res, MESSAGE_SIZE as u64);

        Ok(())
    }

    #[test]
    fn streamed_chipher_eof_sanity() -> io::Result<()> {
        const MESSAGE_SIZE: usize = 1024 * 1024;

        let key: [u8; 32] = [0x11; 32];
        let message = rand::random_iter::<u8>()
            .take(MESSAGE_SIZE)
            .collect::<Vec<_>>();

        let mut sink = Vec::new();
        let mut enc = EncryptWriter::new(&mut sink, key);
        for chunk in message.chunks(4 * 1024) {
            enc.write_all(chunk)?;
        }
        drop(enc);

        let mut dec = DecryptReader::new(Cursor::new(sink), key);

        let mut buf = vec![0u8; MESSAGE_SIZE];
        for i in 0..10 {
            if i == 0 {
                dec.read_exact(&mut buf)?;
            } else {
                assert_eq!(dec.read(&mut buf)?, 0);
            }
        }

        Ok(())
    }
}
