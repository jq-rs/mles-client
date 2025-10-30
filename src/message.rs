use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use blake2::{Blake2b512, Digest};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};
use rand::{RngCore, rngs::OsRng};
use scrypt::{
    Scrypt,
    password_hash::{PasswordHasher, SaltString},
};

// Derive a 256-bit encryption key from a password
pub fn derive_key(password: &str, channel: &str) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(channel.as_bytes());
    let hash = hasher.finalize();
    let salt_bytes = &hash[..16];

    let salt = SaltString::from_b64(&STANDARD_NO_PAD.encode(salt_bytes)).unwrap();
    let password_hash = Scrypt
        .hash_password(password.as_bytes(), salt.as_salt())
        .unwrap();

    let mut key = [0u8; 32];
    key.copy_from_slice(password_hash.hash.unwrap().as_bytes());
    key
}

// Encrypt a message using XChaCha20-Poly1305
pub fn encrypt_message(key: &[u8; 32], plaintext: &str) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let mut nonce = [0u8; 24]; // 24 bytes for XChaCha20
    OsRng.fill_bytes(&mut nonce);

    // Just pass &nonce directly - no XNonce creation needed!
    let ciphertext = cipher.encrypt(&nonce.into(), plaintext.as_bytes()).unwrap();

    [nonce.to_vec(), ciphertext].concat()
}

// Decrypt a received message
pub fn decrypt_message(key: &[u8; 32], encrypted: &[u8]) -> Option<String> {
    if encrypted.len() < 24 {
        return None;
    }
    let (nonce, ciphertext) = encrypted.split_at(24);
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();

    // Just pass nonce directly with .into() - no XNonce creation needed!
    cipher
        .decrypt(nonce.into(), ciphertext)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}
