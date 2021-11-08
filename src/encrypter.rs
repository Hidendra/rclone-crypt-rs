use anyhow::{anyhow, Result};
use sodiumoxide::crypto::secretbox;

use crate::{FILE_HEADER_SIZE, FILE_MAGIC, calculate_nonce, cipher::FileKey};

/// Encrypter instance for a single file.
/// This is not a managed writer; it must be assisted with a separate reader that passes
/// it blocks of data to encrypt.
pub struct Encrypter {
    key: secretbox::Key,
    initial_nonce: secretbox::Nonce,
}

impl Encrypter {
    pub fn new(file_key: &FileKey) -> Result<Self> {
        sodiumoxide::init().map_err(|_| anyhow!("Could not initialize sodiumoxide"))?;
        let initial_nonce = secretbox::gen_nonce();
        
        Ok(Encrypter {
            key: secretbox::Key(*file_key),
            initial_nonce
        })
    }

    fn calculate_nonce(&self, block_id: u64) -> secretbox::Nonce {
        calculate_nonce(self.initial_nonce, block_id)
    }

    pub fn get_file_header(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FILE_HEADER_SIZE);
        out.copy_from_slice(FILE_MAGIC);
        out.copy_from_slice(&self.initial_nonce.0);

        out
    }

    pub fn encrypt_block(&self, block_id: u64, block: &[u8]) -> Vec<u8> {
        let nonce = self.calculate_nonce(block_id);

        secretbox::seal(block, &nonce, &self.key)
    }
}