use super::*;
use rustc_hex::FromHex;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_hash() {
    let output = hash(b"hello world");
    let expected: Vec<u8> = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        .from_hex()
        .unwrap();
    assert_eq!(expected, output);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_hash_fixed() {
    let output = hash_fixed(b"hello world");
    let expected: Vec<u8> = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        .from_hex()
        .unwrap();
    assert_eq!(expected.as_slice(), &output);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_hash32_concat() {
    let h1 = [0u8; 32];
    let h2 = [1u8; 32];
    let mut combined = Vec::new();
    combined.extend_from_slice(&h1);
    combined.extend_from_slice(&h2);
    assert_eq!(hash32_concat(&h1, &h2), hash_fixed(&combined));
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_have_sha_extensions() {
    let _ = have_sha_extensions();
}

#[cfg(feature = "ring")]
mod ring_tests {
    use super::*;

    #[test]
    fn test_ring_impl() {
        let ring_impl = RingImpl;
        let expected: Vec<u8> = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            .from_hex()
            .unwrap();
        assert_eq!(expected, ring_impl.hash(b"hello world"));
        assert_eq!(expected.as_slice(), &ring_impl.hash_fixed(b"hello world"));
    }

    #[test]
    fn test_ring_context() {
        let mut ctx: ring::digest::Context = Sha256Context::new();
        Sha256Context::update(&mut ctx, b"hello world");
        let expected: Vec<u8> = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            .from_hex()
            .unwrap();
        assert_eq!(expected.as_slice(), &Sha256Context::finalize(ctx));
    }
}

#[cfg(any(target_arch = "x86_64", feature = "sha2"))]
mod sha2_tests {
    use super::*;
    use crate::sha2_impl::Sha2CrateImpl;

    #[test]
    fn test_sha2_impl() {
        let sha2_impl = Sha2CrateImpl;
        let expected: Vec<u8> = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            .from_hex()
            .unwrap();
        assert_eq!(expected, sha2_impl.hash(b"hello world"));
        assert_eq!(expected.as_slice(), &sha2_impl.hash_fixed(b"hello world"));
    }

    #[test]
    fn test_sha2_context() {
        let mut ctx: sha2::Sha256 = Sha256Context::new();
        Sha256Context::update(&mut ctx, b"hello world");
        let expected: Vec<u8> = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            .from_hex()
            .unwrap();
        assert_eq!(expected.as_slice(), &Sha256Context::finalize(ctx));
    }
}

#[cfg(feature = "zero_hash_cache")]
mod zero_hash_tests {
    use super::*;

    #[test]
    fn test_zero_hashes() {
        assert_eq!(ZERO_HASHES[0], [0; 32]);
        assert_eq!(
            ZERO_HASHES[1],
            hash32_concat(&ZERO_HASHES[0], &ZERO_HASHES[0])
        );
        assert_eq!(ZERO_HASHES.len(), ZERO_HASHES_MAX_INDEX + 1);
    }
}
