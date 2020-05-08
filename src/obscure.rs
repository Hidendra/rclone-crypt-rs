/// Rclone's "obscure" implementation
/// AKA base64(aes-ctr(val, static_key)) :-(
use anyhow::{anyhow, Result};

use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;
use sodiumoxide::randombytes::randombytes;

// the static key used for obscuring
const OBSCURE_CRYPT_KEY: [u8; 32] = [
    0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d, 0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
    0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb, 0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38,
];

// block size for the cipher
const OBSCURE_BLOCK_SIZE: usize = 16;

fn crypt(data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let key = GenericArray::from_slice(&OBSCURE_CRYPT_KEY);
    let nonce = GenericArray::from_slice(iv);

    let mut cipher = Aes256Ctr::new(&key, &nonce);
    let mut data = data.to_vec();

    cipher.apply_keystream(&mut data);

    Ok(data)
}

pub fn reveal(text: &str) -> Result<String> {
    // text is basically: base64(iv + ciphertext)
    let ciphertext = base64::decode_config(&text, base64::URL_SAFE_NO_PAD)?;

    if ciphertext.len() < OBSCURE_BLOCK_SIZE {
        return Err(anyhow!(
            "Input too short for revealed string. Got length {} but expected >= {}",
            ciphertext.len(),
            OBSCURE_BLOCK_SIZE
        ));
    }

    let buf = &ciphertext[OBSCURE_BLOCK_SIZE..];
    let iv = &ciphertext[0..OBSCURE_BLOCK_SIZE];

    let plaintext = crypt(&buf, &iv)?;
    let result = String::from_utf8(plaintext)?;
    Ok(result)
}

pub fn obscure(plaintext: &str) -> Result<String> {
    let plaintext = plaintext.as_bytes();
    let iv = randombytes(OBSCURE_BLOCK_SIZE);
    let ciphertext = crypt(plaintext, &iv)?;

    // inefficient... rclone uses in-place crypt... obscure is only used for configs
    // so no big deal
    let ciphertext_with_iv = [&iv[..], &ciphertext[..]].concat();

    Ok(base64::encode_config(
        ciphertext_with_iv,
        base64::URL_SAFE_NO_PAD,
    ))
}

#[cfg(test)]
mod tests {
    use crate::obscure::{obscure, reveal};
    use anyhow::Result;

    // TODO
    #[test]
    fn obscure_should_reveal_correctly() -> Result<()> {
        // TODO
        println!("Test");

        let plaintext = "potato".to_string();
        let ciphertext = obscure(&plaintext)?;
        let decoded = reveal(&ciphertext)?;

        assert_eq!(plaintext, decoded);

        Ok(())
    }
}
