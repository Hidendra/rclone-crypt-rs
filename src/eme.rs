/// AES-EME that works with 16-byte blocks up to 2048 bytes.
/// Adapted from the Golang version: https://github.com/rfjakob/eme
use anyhow::{anyhow, Context, Result};

extern crate aes;
use aes::Aes256;
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Ecb};

type Aes256Ecb = Ecb<Aes256, NoPadding>;

pub const NAME_CIPHER_BLOCK_SIZE: usize = 16; // AES block size

// AES-256 is used
pub const EME_KEY_LENGTH: usize = 32;

pub enum TransformDirection {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Debug)]
pub struct AesEme {
    key: [u8; EME_KEY_LENGTH],
}

fn mult_by_two(data: &mut [u8]) {
    let mut tmp = [0u8; 16];
    tmp[0] = data[0].wrapping_mul(2);

    if data[15] >= 128 {
        tmp[0] ^= 135;
    }

    for i in 1..16 {
        tmp[i] = data[i].wrapping_mul(2);

        if data[i - 1] >= 128 {
            tmp[i] += 1;
        }
    }

    data.copy_from_slice(&tmp);
}

fn xor_blocks(out: &mut [u8], in1: &[u8], in2: &[u8]) {
    if in1.len() != in2.len() {
        panic!("xorBlocks length must be the same");
    }

    for i in 0..in1.len() {
        out[i] = in1[i] ^ in2[i];
    }
}

impl AesEme {
    pub fn new(key: [u8; EME_KEY_LENGTH]) -> Result<Self> {
        Ok(AesEme { key })
    }

    fn tabulate_l(&self, m: usize) -> Result<Vec<Vec<u8>>> {
        // set L0 = 2*AESenc(K; 0)
        let mut li = [0u8; 16];

        let cipher = Aes256Ecb::new_from_slices(&self.key, Default::default())?;
        let length = li.len();
        cipher.encrypt(&mut li, length)?;

        // Must be only 16 bytes...
        let mut li: Vec<u8> = li.iter().take(16).cloned().collect();

        let mut ltable = Vec::new();

        for _i in 0..m {
            mult_by_two(&mut li);
            ltable.push(li.clone());
        }

        Ok(ltable)
    }

    fn aes_transform(&self, data: &[u8], direction: &TransformDirection) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        let cipher = Aes256Ecb::new_from_slices(&self.key, Default::default())?;
        let length = data.len();

        match direction {
            TransformDirection::Encrypt => cipher.encrypt(&mut data, length)?,
            TransformDirection::Decrypt => cipher.decrypt(&mut data)?,
        };

        Ok(data)
    }

    pub fn decrypt(&self, tweak: &[u8; NAME_CIPHER_BLOCK_SIZE], data: &[u8]) -> Result<Vec<u8>> {
        let result = self.transform(&tweak, &data, TransformDirection::Decrypt)?;
        Ok(result)
    }

    pub fn encrypt(&self, tweak: &[u8; NAME_CIPHER_BLOCK_SIZE], data: &[u8]) -> Result<Vec<u8>> {
        let result = self.transform(&tweak, &data, TransformDirection::Encrypt)?;
        Ok(result)
    }

    pub fn transform(
        &self,
        tweak: &[u8; NAME_CIPHER_BLOCK_SIZE],
        data: &[u8],
        direction: TransformDirection,
    ) -> Result<Vec<u8>> {
        // In the paper, the tweak is just called "t". Call it the same here to
        // make following the paper easy.
        let t = tweak;

        // In the paper, the plaintext data is called "p" and the ciphertext is
        // called "c". Because encryption and decryption are virtually identical,
        // we share the code and always call the input data "p" and the output data
        // "c", regardless of the direction.
        let p = data;

        if tweak.len() != 16 {
            return Err(anyhow!("Tweak must be of size 16"));
        }

        if p.len() % 16 != 0 {
            return Err(anyhow!("Data size must be a multiple of 16"));
        }

        let num_blocks = p.len() / 16;
        if num_blocks == 0 || num_blocks > 16 * 8 {
            return Err(anyhow!(
                "EME operates on 1 to {} blocks; you passed {}",
                16 * 8,
                num_blocks
            ));
        }

        let mut c = vec![0u8; p.len()];

        let ltable = self.tabulate_l(num_blocks)?;

        let mut ppj = [0u8; 16];
        for i in 0..num_blocks {
            // AES block
            let pj = &p[i * 16..(i + 1) * 16];
            // ppj = 2**(j-1)*L xor pj
            // xorBlocks(ppj, pj, ltable[j])
            xor_blocks(&mut ppj, pj, &ltable[i]);
            // PPPj = AESenc(K; ppj)
            // aes_transform(c[j*16:(j+1)*16], ppj, direction, bc)
            let result = self
                .aes_transform(&ppj, &direction)
                .with_context(|| format!("L131 i = {}", i))?;
            c[i * 16..(i + 1) * 16].copy_from_slice(&result);
        }

        // mp =(xorSum PPPj) xor t
        let mut mp = [0u8; 16];
        // xorBlocks(mp, c[0:16], t)
        xor_blocks(&mut mp, &c[0..16], t);
        for i in 1..num_blocks {
            let in1 = mp.clone();
            xor_blocks(&mut mp, &in1, &c[i * 16..(i + 1) * 16]);
        }

        // mc = AESenc(K; mp)
        // aes_transform(mc, mp, direction, bc)
        let mc = self
            .aes_transform(&mp, &direction)
            .with_context(|| format!("test2"))?;

        // m = mp xor mc
        let mut m = [0u8; 16];
        xor_blocks(&mut m, &mp, &mc);
        let mut cccj = [0u8; 16];
        for i in 1..num_blocks {
            mult_by_two(&mut m);
            // cccj = 2**(j-1)*m xor PPPj
            xor_blocks(&mut cccj, &c[i * 16..(i + 1) * 16], &m);
            c[i * 16..(i + 1) * 16].copy_from_slice(&cccj);
        }

        // ccc1 = (xorSum cccj) xor t xor mc
        let mut ccc1 = [0u8; 16];
        xor_blocks(&mut ccc1, &mc, t);
        for i in 1..num_blocks {
            let in1 = ccc1.clone();
            xor_blocks(&mut ccc1, &in1, &c[i * 16..(i + 1) * 16]);
        }
        c[0..16].copy_from_slice(&ccc1);

        for i in 0..num_blocks {
            // CCj = AES-enc(K; cccj)
            let mut block = &mut c[i * 16..(i + 1) * 16];
            // aes_transform(c[j*16:(j+1)*16], c[j*16:(j+1)*16], direction, bc)
            let result = self
                .aes_transform(block, &direction)
                .with_context(|| format!("test3"))?;
            block.copy_from_slice(&result);
            // Cj = 2**(j-1)*L xor CCj
            // xorBlocks(c[j*16:(j+1)*16], c[j*16:(j+1)*16], ltable[j])
            let in1 = block.to_vec();
            xor_blocks(&mut block, &in1, &ltable[i]);
        }

        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use crate::eme::{AesEme, TransformDirection};
    use anyhow::Result;
    use data_encoding::HEXLOWER;

    #[test]
    fn eme_should_encrypt_16_bytes_encrypts_successfully() -> Result<()> {
        let key = [0u8; 32];
        let tweak = [0u8; 16];
        let plaintext = [0u8; 16];

        let eme = AesEme::new(key)?;
        let ciphertext = eme.transform(&tweak, &plaintext, TransformDirection::Encrypt)?;
        let back_to_plaintext = eme.transform(&tweak, &ciphertext, TransformDirection::Decrypt)?;

        assert_eq!(
            "f1b9ce8ca15a4ba9fb476905434b9fd3",
            HEXLOWER.encode(&ciphertext)
        );
        assert_eq!(
            "00000000000000000000000000000000",
            HEXLOWER.encode(&back_to_plaintext)
        );

        Ok(())
    }
}
