use openssl::symm::{encrypt, decrypt, Cipher, Crypter, Mode};

use openssl::rand::rand_bytes;

use ring::{pbkdf2};
use std::{num::NonZeroU32};

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;

pub struct OpensslEncrypt {
    key: Vec<u8>,
    iv: Vec<u8>,
    magic_header: Vec<u8>,
    cipher: Cipher,
    block_size: usize,
    encrypter: openssl::symm::Crypter,
    decrypter: openssl::symm::Crypter,
    add_magic_header: bool,
    remove_magic_header: bool,
}

trait GetRandomBytes {
    fn get_random_bytes(length: usize) -> Vec<u8> {
        let mut buf = vec![0; length];
        rand_bytes(&mut buf).unwrap();
        return buf;
    }
}

#[cfg(not(test))]
impl GetRandomBytes for OpensslEncrypt {}

impl OpensslEncrypt {
    pub fn new(password: String, cipher: Cipher, iteration_count: u32) -> OpensslEncrypt {
        let password_vec = password.as_bytes().to_vec();
        let iterations = NonZeroU32::new(Some(iteration_count).unwrap_or(10000)).unwrap();
        let salt = OpensslEncrypt::get_random_bytes(8);

        let iv_length = cipher.iv_len().expect("Could not get iv length from cipher. This cipher is not supported.");
        let key_length = cipher.key_len();

        let key_and_iv_length = iv_length + key_length;
        let mut pbkdf2_key_iv = vec![0; key_and_iv_length];
        
        pbkdf2::derive(PBKDF2_ALG, iterations,  &salt, &password_vec, &mut pbkdf2_key_iv);

        let key = pbkdf2_key_iv[0..key_length].to_vec();
        let iv = pbkdf2_key_iv[key_length..key_and_iv_length].to_vec();
        
        let block_size = cipher.block_size();
        let magic_header = ["Salted__".as_bytes(), &salt].concat();
        let encrypter = Crypter::new(
            cipher,
            Mode::Encrypt,
            &key,
            Some(&iv)).unwrap();
        let decrypter = Crypter::new(
            cipher,
            Mode::Decrypt,
            &key,
            Some(&iv)).unwrap();

        return OpensslEncrypt {
            key, 
            iv,
            magic_header,
            cipher, 
            block_size,
            encrypter,
            decrypter,
            add_magic_header: true,
            remove_magic_header: true,
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
    pub fn encrypt_chunk(&mut self, chunk: &Vec<u8>) -> Vec<u8> {
        let mut ciphertext = vec![0; chunk.len() + self.block_size];

        let count = self.encrypter.update(&chunk, &mut ciphertext).unwrap();
        ciphertext.truncate(count);

        if self.add_magic_header {
            self.add_magic_header = false;
            return [&self.magic_header[..], &ciphertext[..]].concat();
        } else {
            return ciphertext;
        }
    }
    pub fn encrypter_finalize(&mut self) -> Vec<u8> {
        let mut ciphertext = vec![0; self.block_size];
        let final_length = self.encrypter.finalize(&mut ciphertext).unwrap();
        ciphertext.truncate(final_length);
        return ciphertext;
    }
    pub fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        let data_without_magic_header = &data[16..];
        let decrypted_data = decrypt(
            self.cipher,
            &self.key,
            Some(&self.iv),
            &data_without_magic_header).unwrap();
        return decrypted_data;
    }
    pub fn decrypt_chunk(&mut self, chunk: &Vec<u8>) -> Vec<u8> {
        let reformatted_data;
        if self.remove_magic_header {
            println!("removing magic header");
            self.remove_magic_header = false;
            reformatted_data = &chunk[16..];
        } else {
            reformatted_data = chunk;
        }

        let mut plain_text = vec![0; reformatted_data.len() + self.block_size];

        let count = self.decrypter.update(&reformatted_data, &mut plain_text).unwrap();
        plain_text.truncate(count);

        return plain_text;
    }
    pub fn decrypter_finalize(&mut self) -> Vec<u8> {
        let mut ciphertext = vec![0; self.block_size];
        let final_length = self.decrypter.finalize(&mut ciphertext).unwrap();
        ciphertext.truncate(final_length);
        return ciphertext;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // implement test version of get_random_bytes that returns static value
    #[cfg(test)]
    impl super::GetRandomBytes for OpensslEncrypt {
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
    fn can_encrypt_128_correctly() {
        let mut openssl_encrypt = OpensslEncrypt::new("password".to_string(), Cipher::aes_128_cbc(), 10000);
        let encrypted_data = openssl_encrypt.encrypt("some data".as_bytes().to_vec());
        // println!("{:X?}", encrypted_data);
        assert_eq!(
            b"\x53\x61\x6C\x74\x65\x64\x5F\x5F\x53\x61\x23\x11\x23\x56\x74\x12\x68\x4B\xA4\xA2\x6F\xB6\x96\x91\x11\x64\x32\x21\xF9\x2A\xAB\x92".to_vec(),
            encrypted_data
        );
    }
    #[test]
    fn can_encrypt_chunks_correctly() {
        let mut openssl_encrypt = OpensslEncrypt::new("password".to_string(), Cipher::aes_256_cbc(), 10000);
        let encrypted_chunk1 = openssl_encrypt.encrypt_chunk(&"some".as_bytes().to_vec());
        let encrypted_chunk2 = openssl_encrypt.encrypt_chunk(&" ".as_bytes().to_vec());
        let encrypted_chunk3 = openssl_encrypt.encrypt_chunk(&"data".as_bytes().to_vec());
        let encrypted_final_chunk = openssl_encrypt.encrypter_finalize();
        assert_eq!(
            b"\x53\x61\x6c\x74\x65\x64\x5f\x5f\x53\x61\x23\x11\x23\x56\x74\x12\x72\x30\x32\x8f\xca\x92\x3c\x3b\x53\x99\x11\x99\x14\x32\x79\x78".to_vec(),
            [&encrypted_chunk1[..], &encrypted_chunk2[..], &encrypted_chunk3[..], &encrypted_final_chunk[..]].concat()
        );
    }
    #[test]
    fn can_decrypt_correctly() {
        let mut openssl_encrypt = OpensslEncrypt::new("password".to_string(), Cipher::aes_256_cbc(), 10000);
        let encrypted_data = b"\x53\x61\x6c\x74\x65\x64\x5f\x5f\x53\x61\x23\x11\x23\x56\x74\x12\x72\x30\x32\x8f\xca\x92\x3c\x3b\x53\x99\x11\x99\x14\x32\x79\x78".to_vec();
        let decrypted_data = openssl_encrypt.decrypt(encrypted_data);

        assert_eq!(b"some data", &decrypted_data[..]);
    }
    #[test]
    fn can_decrypt_chunks_correctly() {
        let mut openssl_encrypt = OpensslEncrypt::new("password".to_string(), Cipher::aes_256_cbc(), 10000);
        let decrypted_chunk1 = openssl_encrypt.decrypt_chunk(&b"\x53\x61\x6c\x74\x65\x64\x5f\x5f\x53\x61\x23\x11\x23\x56\x74\x12\x72".to_vec());
        let decrypted_chunk2 = openssl_encrypt.decrypt_chunk(&b"\x30\x32\x8f\xca\x92\x3c\x3b\x53\x99\x11".to_vec());
        let decrypted_chunk3 = openssl_encrypt.decrypt_chunk(&b"\x99\x14\x32\x79\x78".to_vec());
        let decrypted_final_chunk = openssl_encrypt.decrypter_finalize();
        assert_eq!(
            "some data".as_bytes().to_vec(),
            [&decrypted_chunk1[..], &decrypted_chunk2[..], &decrypted_chunk3[..], &decrypted_final_chunk[..]].concat()
        );
    }
}
