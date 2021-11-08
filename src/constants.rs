use sodiumoxide::crypto::secretbox;

pub const FILE_MAGIC: &[u8] = b"RCLONE\x00\x00";
pub const FILE_NONCE_SIZE: usize = 24;
pub const FILE_HEADER_SIZE: usize = FILE_MAGIC.len() + FILE_NONCE_SIZE;

// Each block has an authenticated header
pub const BLOCK_HEADER_SIZE: usize = secretbox::MACBYTES;
pub const BLOCK_DATA_SIZE: usize = 64 * 1024;
pub const BLOCK_SIZE: usize = BLOCK_HEADER_SIZE + BLOCK_DATA_SIZE;
