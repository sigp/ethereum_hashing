//! Optimized SHA256 for use in Ethereum.
//!
//! The initial purpose of this crate was to provide an abstraction over the hash function used in
//! the beacon chain. The hash function changed during the specification process, so defining it
//! once in this crate made it easy to replace.
//!
//! Now this crate serves primarily as a wrapper over two SHA256 crates: `sha2` and `ring` – which
//! it switches between at runtime based on the availability of SHA intrinsics.

mod sha2_impl;

pub use self::DynamicContext as Context;

#[cfg(target_arch = "x86_64")]
use sha2_impl::Sha2CrateImpl;

#[cfg(feature = "zero_hash_cache")]
use std::sync::LazyLock;

/// Length of a SHA256 hash in bytes.
pub const HASH_LEN: usize = 32;

/// Returns the digest of `input` using the best available implementation.
pub fn hash(input: &[u8]) -> Vec<u8> {
    DynamicImpl::best().hash(input)
}

/// Hash function returning a fixed-size array (to save on allocations).
///
/// Uses the best available implementation based on CPU features.
pub fn hash_fixed(input: &[u8]) -> [u8; HASH_LEN] {
    DynamicImpl::best().hash_fixed(input)
}

/// Compute the hash of two slices concatenated.
pub fn hash32_concat(h1: &[u8], h2: &[u8]) -> [u8; 32] {
    let mut ctxt = DynamicContext::new();
    ctxt.update(h1);
    ctxt.update(h2);
    ctxt.finalize()
}

/// Context trait for abstracting over implementation contexts.
pub trait Sha256Context {
    fn new() -> Self;

    fn update(&mut self, bytes: &[u8]);

    fn finalize(self) -> [u8; HASH_LEN];
}

/// Top-level trait implemented by both `sha2` and `ring` implementations.
pub trait Sha256 {
    type Context: Sha256Context;

    fn hash(&self, input: &[u8]) -> Vec<u8>;

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN];
}

/// Implementation of SHA256 using the `ring` crate (fastest on CPUs without SHA extensions).
pub struct RingImpl;

impl Sha256Context for ring::digest::Context {
    fn new() -> Self {
        Self::new(&ring::digest::SHA256)
    }

    fn update(&mut self, bytes: &[u8]) {
        self.update(bytes)
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        let mut output = [0; HASH_LEN];
        output.copy_from_slice(self.finish().as_ref());
        output
    }
}

impl Sha256 for RingImpl {
    type Context = ring::digest::Context;

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, input)
            .as_ref()
            .into()
    }

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        let mut ctxt = Self::Context::new(&ring::digest::SHA256);
        ctxt.update(input);
        ctxt.finalize()
    }
}

/// Default dynamic implementation that switches between available implementations.
pub enum DynamicImpl {
    #[cfg(target_arch = "x86_64")]
    Sha2,
    Ring,
}

// Runtime latch for detecting the availability of SHA extensions on x86_64.
//
// Inspired by the runtime switch within the `sha2` crate itself.
#[cfg(target_arch = "x86_64")]
cpufeatures::new!(x86_sha_extensions, "sha", "sse2", "ssse3", "sse4.1");

#[inline(always)]
pub fn have_sha_extensions() -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_sha_extensions::get();

    #[cfg(not(target_arch = "x86_64"))]
    return false;
}

impl DynamicImpl {
    /// Choose the best available implementation based on the currently executing CPU.
    #[inline(always)]
    pub fn best() -> Self {
        #[cfg(target_arch = "x86_64")]
        if have_sha_extensions() {
            Self::Sha2
        } else {
            Self::Ring
        }

        #[cfg(not(target_arch = "x86_64"))]
        Self::Ring
    }
}

impl Sha256 for DynamicImpl {
    type Context = DynamicContext;

    #[inline(always)]
    fn hash(&self, input: &[u8]) -> Vec<u8> {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Sha2 => Sha2CrateImpl.hash(input),
            Self::Ring => RingImpl.hash(input),
        }
    }

    #[inline(always)]
    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Sha2 => Sha2CrateImpl.hash_fixed(input),
            Self::Ring => RingImpl.hash_fixed(input),
        }
    }
}

/// Context encapsulating all implemenation contexts.
///
/// This enum ends up being 8 bytes larger than the largest inner context.
pub enum DynamicContext {
    #[cfg(target_arch = "x86_64")]
    Sha2(sha2::Sha256),
    Ring(ring::digest::Context),
}

impl Sha256Context for DynamicContext {
    fn new() -> Self {
        match DynamicImpl::best() {
            #[cfg(target_arch = "x86_64")]
            DynamicImpl::Sha2 => Self::Sha2(Sha256Context::new()),
            DynamicImpl::Ring => Self::Ring(Sha256Context::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Sha2(ctxt) => Sha256Context::update(ctxt, bytes),
            Self::Ring(ctxt) => Sha256Context::update(ctxt, bytes),
        }
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Sha2(ctxt) => Sha256Context::finalize(ctxt),
            Self::Ring(ctxt) => Sha256Context::finalize(ctxt),
        }
    }
}

/// The max index that can be used with `ZERO_HASHES`.
#[cfg(feature = "zero_hash_cache")]
pub const ZERO_HASHES_MAX_INDEX: usize = 48;

#[cfg(feature = "zero_hash_cache")]
/// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
pub static ZERO_HASHES: LazyLock<Vec<[u8; HASH_LEN]>> = LazyLock::new(|| {
    let mut hashes = vec![[0; HASH_LEN]; ZERO_HASHES_MAX_INDEX + 1];

    for i in 0..ZERO_HASHES_MAX_INDEX {
        hashes[i + 1] = hash32_concat(&hashes[i], &hashes[i]);
    }

    hashes
});

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_hashing() {
        let input: Vec<u8> = b"hello world".as_ref().into();

        let output = hash(input.as_ref());
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let expected: Vec<u8> = expected_hex.from_hex().unwrap();
        assert_eq!(expected, output);
    }

    #[cfg(feature = "zero_hash_cache")]
    mod zero_hash {
        use super::*;

        #[test]
        fn zero_hash_zero() {
            assert_eq!(ZERO_HASHES[0], [0; 32]);
        }
    }
}
