# shami_rs

`shami_rs` is a pure rust implementation of Shamir's Secret Sharing. It turns a secret into a number of shares and with the possesion of some or all of these the secret can be restored.

## Features

- Base "textbook" implementation of Shamir's Secret Sharing.
- XChaCha20-Poly1305 AEAD wrapper, that encrypts the secret before shares are created.
- BIP mnemonic wrapper that results in shorter shares when the secret is a BIP mnemonic.
- Optional padding so that shares are a multiple of 8 bytes.
- No predetermined encoding (Base64 recommended)
- **Experimental** - Up to 2 predefined shares before creating the rest of the shares.

# Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
shami_rs = { git = "https://github.com/euandeas/shami_rs" }
```

Or this if you have the source code locally:
```toml
[dependencies]
shami_rs = { path = "../shami_rs" }
```

# Usage

## Base

```Rust
use shami_rs::base;

fn main() {
    let msg = "Hello World!";
    
    let shares = match build_shares(msg.as_bytes(), 3, 5, false) {
        Ok(shares) => shares,
        Err(e) => panic!(),
    };
    
    let secret = match rebuild_secret(shares){
        Ok(secret) => secret,
        Err(e) => panic!(),
    };
    
    assert_eq!(msg.as_bytes.to_vec(), secret);
}
```

## Experimental

shami_rs contains an `experimental` feature that unlocks the ability to create shares with up to 2 predefined shares. As stated this is experimental, so the security implications have not been fully investigated. Use at your own risk! 

If you are going to use this feature it is important to make sure that these shares are uniformly random and have high entropy.

```Rust
use shami_rs::base;

fn main() {
   let pre_shares = vec![b"share1".to_vec(), b"share2".to_vec()]; // These are very bad predefined shares!
   let msg = "Hello!";

   let shares = match build_shares_predefined(msg.as_bytes(), pre_shares, 3, 5, false) {
        Ok(shares) => shares,
        Err(e) => panic!(),
    };
    
    let secret = match rebuild_secret(shares){
        Ok(secret) => secret,
        Err(e) => panic!(),
    };
    
    assert_eq!(msg.as_bytes.to_vec(), secret);
}
```

# Technical Details

# Security

I am not a cryptologist or security expert. This implementation of Shamir's Secret Sharing was designed and created by investigating other implementations and reading various resources on the topic. I believe that I have implemented it correctly based on the fact that it behaves as expected.

To the best of my knowledge, this program is reasonably safe to use nut ultimately, it's your responsibility to use the software carefully. The source code is also readily available, so it can be reviewed and/or audited.

If you discover any problems with the library, please let me know!

# License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

