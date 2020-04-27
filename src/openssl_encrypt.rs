use openssl::symm::{encrypt, decrypt, Cipher};

use openssl::rand::rand_bytes;

use ring::{pbkdf2};
use std::{num::NonZeroU32};

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;

pub struct OpensslEncrypt {
    key: Vec<u8>,
    iv: Vec<u8>,
    magic_header: Vec<u8>,
    cipher: Cipher,
}

trait GetRandomBytes {
    fn get_random_bytes(length: usize) -> Vec<u8> {
        let mut buf = vec![0; length];
        rand_bytes(&mut buf).unwrap();
        return buf;
    }
}

impl GetRandomBytes for OpensslEncrypt {}

impl OpensslEncrypt {
    fn get_iv_salt_key(password: String, iteration_count: u32 ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let password_vec = password.as_bytes().to_vec();
        let iterations = NonZeroU32::new(Some(iteration_count).unwrap_or(10000)).unwrap();
        let salt = OpensslEncrypt::get_random_bytes(8);
        let mut pbkdf2_key_iv = [0; 48]; // 256 bits + 128 bits
        
        pbkdf2::derive(PBKDF2_ALG, iterations,  &salt, &password_vec, &mut pbkdf2_key_iv);

        let key = pbkdf2_key_iv[0..32].to_vec(); // 256 bits
        let iv = pbkdf2_key_iv[32..48].to_vec(); // 128 bits
        
        return (key, iv, salt);
    }
    pub fn new(password: String, cipher: Cipher, iteration_count: u32) -> OpensslEncrypt {
        let (key, iv, salt) = OpensslEncrypt::get_iv_salt_key(password, iteration_count);

        // let block_size = cipher.block_size();
        let magic_header = ["Salted__".as_bytes(), &salt].concat();

        return OpensslEncrypt {
            key, 
            iv,
            magic_header,
            cipher, 
        };
    }
    pub fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        let ciphertext = encrypt(
            self.cipher,
            &self.key,
            Some(&self.iv),
            &data).unwrap();
        
        return [&self.magic_header[..], &ciphertext[..]].concat();
    }
    pub fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        let data_without_magic_header = &data[16..];
        return decrypt(
            self.cipher,
            &self.key,
            Some(&self.iv),
            &data_without_magic_header).unwrap();
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    // mock/override default get_random_bytes to return static value
    impl super::GetRandomBytesTest for OpensslEncrypt {
        fn get_random_bytes(length: usize) -> Vec<u8> {
            return b"\x53\x61\x23\x11\x23\x56\x74\x12\x34\x12\x23\x23\x23\x23\x54"[..length].to_vec();
        }
    }

    #[test]
    fn can_encrypt_correctly() {
        let mut openssl_encrypt = OpensslEncrypt::new("password".to_string(), Cipher::aes_256_cbc(), 10000);
        let encrypted_data = openssl_encrypt.encrypt("some data".as_bytes().to_vec());
        assert_eq!(
            b"\x53\x61\x6c\x74\x65\x64\x5f\x5f\x53\x61\x23\x11\x23\x56\x74\x12\x72\x30\x32\x8f\xca\x92\x3c\x3b\x53\x99\x11\x99\x14\x32\x79\x78".to_vec(),
            encrypted_data
        );
    }
    #[test]
    fn can_decrypt_correctly() {
        let mut openssl_encrypt = OpensslEncrypt::new("password".to_string(), Cipher::aes_256_cbc(), 10000);
        let encrypted_data = b"\x53\x61\x6c\x74\x65\x64\x5f\x5f\x53\x61\x23\x11\x23\x56\x74\x12\x72\x30\x32\x8f\xca\x92\x3c\x3b\x53\x99\x11\x99\x14\x32\x79\x78".to_vec();
        let decrypted_data = openssl_encrypt.decrypt(encrypted_data);

        assert_eq!(b"some data", &decrypted_data[..]);
    }
}
