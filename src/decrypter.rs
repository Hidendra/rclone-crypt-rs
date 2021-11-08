use crate::{calculate_nonce, cipher::FileKey, FILE_MAGIC};
use anyhow::{anyhow, Result};
use arrayref::array_ref;
use sodiumoxide::crypto::secretbox;

/// Decrypter instance for a single file.
/// This is not a managed reader; it must be assisted with a separate reader that passes
/// it blocks of encrypted data of interest.
pub struct Decrypter {
    key: secretbox::Key,
    initial_nonce: secretbox::Nonce,
}

impl Decrypter {
    pub fn new(file_key: &FileKey, file_header: &[u8]) -> Result<Self> {
        sodiumoxide::init().map_err(|_| anyhow!("Could not initialize sodiumoxide"))?;
        if &file_header[..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(anyhow!("Invalid file magic in file"));
        }

        let nonce = secretbox::Nonce(*array_ref!(file_header, FILE_MAGIC.len(), 24));

        Ok(Decrypter {
            key: secretbox::Key(*file_key),
            initial_nonce: nonce,
        })
    }

    fn calculate_nonce(&self, block_id: u64) -> secretbox::Nonce {
        calculate_nonce(self.initial_nonce, block_id)
    }

    /// Decrypts a block using the nonce and password state
    /// The block must be of max BLOCK_SIZE bytes; the final block in the file
    /// may be lower than this but otherwise block will be of that exact size.
    pub fn decrypt_block(&self, block_id: u64, block: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.calculate_nonce(block_id);

        secretbox::open(block, &nonce, &self.key)
            .map_err(|_| anyhow!("Failed to decrypt block of size {}", block.len()))
    }
}
