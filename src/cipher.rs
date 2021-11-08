/// Cipher utilities for rclone-crypt
/// Note: ONLY Name Encryption is currently supported; not obfuscation.
use anyhow::{anyhow, Result};

use crate::eme;
use crate::eme::{AesEme, NAME_CIPHER_BLOCK_SIZE};
use arrayref::array_ref;
use block_modes::block_padding::{Padding, Pkcs7};
use data_encoding::{BASE32HEX, BASE32HEX_NOPAD};
use scrypt::{scrypt, Params};
use std::path::{Component, Path, PathBuf};

const TOTAL_KEY_SIZE: usize = 32 + 32 + eme::NAME_CIPHER_BLOCK_SIZE; // this should probably be defined more nicely

pub type FileKey = [u8; 32];
pub type NameKey = [u8; 32];
pub type TweakKey = [u8; eme::NAME_CIPHER_BLOCK_SIZE];

#[derive(Clone, Debug)]
pub struct Cipher {
    /// The main password or passphrase
    /// This is used as the main crypto key
    /// This must be revealed from the obscured password (i.e. password from the rclone config)
    password: String,

    /// Salt used for nacl
    /// This must be revealed from the obscured salt (i.e. password2 from the rclone config)
    salt: String,

    /// AES-EME construct. Used for file name crypto.
    eme: AesEme,

    /// The key used for file encryption.
    /// This is generated from the password and salt using scrypt.
    pub file_key: FileKey,

    /// The key used for name encryption.
    /// This is generated from the password and salt using scrypt.
    /// TODO this might be obfuscation only
    pub name_key: NameKey,

    /// The tweak used for name encryption.
    /// This is generated from the password and salt using scrypt.
    pub tweak_key: TweakKey,
}

/// Calculates the keys using scrypt.
/// This key is used together with file nonce to encrypt/decrypt file and name data.
fn generate_keys(password: &str, salt: &str) -> Result<(FileKey, NameKey, TweakKey)> {
    let params = Params::new(14, 8, 1)?; // log2(16384) = 14

    let mut key = [0u8; TOTAL_KEY_SIZE];
    scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut key)?;

    Ok((
        *array_ref!(key, 0, 32),
        *array_ref!(key, 32, 32),
        *array_ref!(key, 64, eme::NAME_CIPHER_BLOCK_SIZE),
    ))
}

fn encode_segment(data: &[u8]) -> String {
    BASE32HEX_NOPAD.encode(data).to_lowercase()
}

fn decode_segment(name: &str) -> Result<Vec<u8>> {
    let rounded_up_chars = (name.len() + 7) & (!7);
    let equals = rounded_up_chars - name.len();

    let result = name.to_uppercase() + &"========"[..equals];
    let result = BASE32HEX.decode(result.as_bytes())?;
    Ok(result)
}

impl Cipher {
    pub fn new(password: String, salt: String) -> Result<Self> {
        let keys = generate_keys(&password, &salt)?;

        Ok(Cipher {
            file_key: keys.0,
            name_key: keys.1,
            tweak_key: keys.2,
            eme: AesEme::new(keys.1)?,
            password,
            salt,
        })
    }

    pub fn encrypt_segment(&self, segment: &str) -> Result<String> {
        if segment.is_empty() {
            return Ok(String::new());
        }

        let rounded_up_size =
            ((segment.len() / NAME_CIPHER_BLOCK_SIZE) + 1) * NAME_CIPHER_BLOCK_SIZE;

        let mut buffer = vec![0u8; rounded_up_size];
        buffer[..segment.len()].copy_from_slice(segment.as_bytes());

        if let Err(_error) = Pkcs7::pad(&mut buffer, segment.len(), NAME_CIPHER_BLOCK_SIZE) {
            return Err(anyhow!(
                "Pkcs7 padding failed on message of size {}",
                segment.len()
            ));
        }

        let encrypted = self.eme.encrypt(&self.tweak_key, &buffer)?;
        let encoded = encode_segment(&encrypted);

        Ok(encoded)
    }

    pub fn decrypt_segment(&self, segment: &str) -> Result<String> {
        let decoded = decode_segment(segment)?;

        if decoded.is_empty() || decoded.len() % NAME_CIPHER_BLOCK_SIZE != 0 {
            return Err(anyhow!("Decoded name is not a multiple of block size"));
        }

        if decoded.len() > 2048 {
            return Err(anyhow!("Decoded name is too long"));
        }

        // paddedPlaintext := eme.Transform(c.block, c.nameTweak[:], rawCiphertext, eme.DirectionDecrypt)
        let padded_plaintext = self.eme.decrypt(&self.tweak_key, &decoded)?;

        // plaintext, err := pkcs7.Unpad(nameCipherBlockSize, paddedPlaintext)
        let plaintext = match Pkcs7::unpad(&padded_plaintext) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Failed to unpad padded plaintext")),
        };

        let plaintext = String::from_utf8(plaintext.to_vec())?;
        Ok(plaintext)
    }

    pub fn encrypt_path(&self, path: &Path) -> Result<PathBuf> {
        let mut result = PathBuf::new();

        for component in path.components() {
            match component {
                Component::Normal(p) => result.push(self.encrypt_segment(p.to_str().unwrap())?),
                c => result.push(c),
            }
        }

        Ok(result)
    }

    pub fn decrypt_path(&self, path: &Path) -> Result<PathBuf> {
        let mut result = PathBuf::new();

        for component in path.components() {
            match component {
                Component::Normal(p) => result.push(self.decrypt_segment(p.to_str().unwrap())?),
                c => result.push(c),
            }
        }

        Ok(result)
    }

    pub fn encrypt_file_name(&self, name: &str) -> Result<String> {
        let segments = name
            .split('/')
            .map(|seg| self.encrypt_segment(seg))
            .collect::<Result<Vec<String>>>()?;

        Ok(segments.join("/"))
    }

    pub fn decrypt_file_name(&self, name: &str) -> Result<String> {
        let segments = name
            .split('/')
            .map(|seg| self.decrypt_segment(seg))
            .collect::<Result<Vec<String>>>()?;

        Ok(segments.join("/"))
    }
}
