# rw-aes-gcm

Crate implements `std::io::{Read, Write}` traits for encrypting and decrypting data using AES-GCM.

## Usage

```rust
use rw_aes_gcm::{EncryptWriter, DecryptReader};
use std::io::{Cursor, Read, Write};

let key = [0x11; 32];

let mut sink = Vec::new();
let mut enc = EncryptWriter::new(&mut sink, key);
writeln!(enc, "hello world!").unwrap();
enc.flush().unwrap();
writeln!(enc, "another line").unwrap();

drop(enc);

let mut dec = DecryptReader::new(Cursor::new(sink), key);
let mut out = String::new();
dec.read_to_string(&mut out).unwrap();

assert_eq!(out, "hello world!\nanother line\n");
```
