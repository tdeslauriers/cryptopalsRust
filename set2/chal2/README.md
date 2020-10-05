
* *above solution intentionally verbose: sorting out rust tdd methodology.*
* *correct/rust library implementation below. Doing it manually for conceptual learning*

**note:** pkcs7 standard: pad block with bytes with value equal to the number of bytes added.

# Implement PKCS#7 padding


A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

```"YELLOW SUBMARINE"```

... padded to 20 bytes would be:

```"YELLOW SUBMARINE\x04\x04\x04\x04"```

# Rust library/crate impl

```rust
use block_padding::{Pkcs7, Padding};

let msg = b"test";
let n = msg.len();
let mut buffer = [0xff; 16];
buffer[..n].copy_from_slice(msg);
let padded_msg = Pkcs7::pad(&mut buffer, n, 8).unwrap();
assert_eq!(padded_msg, b"test\x04\x04\x04\x04");
assert_eq!(Pkcs7::unpad(&padded_msg).unwrap(), msg);
 
let padded_msg = Pkcs7::pad(&mut buffer, n, 2).unwrap();
assert_eq!(padded_msg, b"test\x02\x02");
assert_eq!(Pkcs7::unpad(&padded_msg).unwrap(), msg);
 
assert!(Pkcs7::unpad(&buffer).is_err());```
