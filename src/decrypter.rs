use crate::cipher::FileKey;
use anyhow::{anyhow, Result};
use arrayref::array_ref;
use sodiumoxide::crypto::secretbox;

pub const FILE_MAGIC: &[u8] = b"RCLONE\x00\x00";
pub const FILE_NONCE_SIZE: usize = 24;
pub const FILE_HEADER_SIZE: usize = FILE_MAGIC.len() + FILE_NONCE_SIZE;

// Each block has an authenticated header
pub const BLOCK_HEADER_SIZE: usize = secretbox::MACBYTES;
pub const BLOCK_DATA_SIZE: usize = 64 * 1024;
pub const BLOCK_SIZE: usize = BLOCK_HEADER_SIZE + BLOCK_DATA_SIZE;

/// Decrypter instance for a single file.
/// This is not a managed reader; it must be assisted with a separate reader that passes
/// it blocks of encrypted data of interest.
pub struct Decrypter {
    key: secretbox::Key,
    initial_nonce: secretbox::Nonce,
    // nonce: secretbox::Nonce,
}

impl Decrypter {
    pub fn new(file_key: &FileKey, file_header: &[u8]) -> Result<Self> {
        if &file_header[..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(anyhow!("Invalid file magic in file"));
        }

        let nonce = secretbox::Nonce(array_ref!(file_header, FILE_MAGIC.len(), 24).clone());

        Ok(Decrypter {
            key: secretbox::Key(file_key.clone()),
            // nonce: nonce,
            initial_nonce: nonce,
        })
    }

    fn calculate_nonce(&self, block_id: u64) -> secretbox::Nonce {
        let mut nonce = secretbox::Nonce(self.initial_nonce.0.clone());

        if block_id == 0 {
            return nonce;
        }

        let mut x = block_id;
        let mut carry: u16 = 0;

        for i in 0..8 {
            let digit = nonce.0[i];
            let x_digit = x as u8;
            x >>= 8;
            carry += digit as u16 + x_digit as u16;
            nonce.0[i] = carry as u8;
            carry >>= 8;
        }

        if carry != 0 {
            for i in carry as usize..FILE_NONCE_SIZE {
                let digit = nonce.0[i];
                let new_digit = digit + 1;
                nonce.0[i] = new_digit;
                if new_digit >= digit {
                    // no carry
                    break;
                }
            }
        }

        nonce
    }

    /// Decrypts a block using the nonce and password state
    /// The block must be of max BLOCK_SIZE bytes; the final block in the file
    /// may be lower than this but otherwise block will be of that exact size.
    pub fn decrypt_block(&self, block_id: u64, block: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.calculate_nonce(block_id);

        match secretbox::open(&block, &nonce, &self.key) {
            Ok(decrypted) => Ok(decrypted),
            Err(_) => Err(anyhow!("Failed to decrypt block of size {}", block.len())),
        }
    }
}
