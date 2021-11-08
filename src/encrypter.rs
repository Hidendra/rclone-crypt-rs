use sodiumoxide::crypto::secretbox;

pub struct Encrypter {
    key: secretbox::Key,
    initial_nonce: secretbox::Nonce,
}