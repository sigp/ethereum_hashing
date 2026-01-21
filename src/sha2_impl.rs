// This implementation is compiled on x86_64 (always has sha2) or when the sha2 feature is enabled.
#![cfg(any(target_arch = "x86_64", feature = "sha2"))]

use crate::{Sha256, Sha256Context, HASH_LEN};
use sha2::Digest;

/// Implementation of SHA256 using the `sha2` crate (fastest on x86_64 CPUs with SHA extensions).
pub struct Sha2CrateImpl;

impl Sha256Context for sha2::Sha256 {
    fn new() -> Self {
        sha2::Digest::new()
    }

    fn update(&mut self, bytes: &[u8]) {
        sha2::Digest::update(self, bytes)
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        sha2::Digest::finalize(self).into()
    }
}

impl Sha256 for Sha2CrateImpl {
    type Context = sha2::Sha256;

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        Self::Context::digest(input).into_iter().collect()
    }

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        Self::Context::digest(input).into()
    }
}
