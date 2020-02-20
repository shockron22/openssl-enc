use openssl::symm::{Cipher, Mode, Crypter};
use openssl::rand::rand_bytes;

use ring::{pbkdf2};
use std::{num::NonZeroU32};

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static ONE_KB: usize = 1024;

pub struct OpensslEncrypt {
    pub password: Vec<u8>,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub salt: Vec<u8>,
}

impl Default for OpensslEncrypt {
    fn default() -> OpensslEncrypt {
        return OpensslEncrypt {
            password: OpensslEncrypt::get_random_bytes(50),
            salt: OpensslEncrypt::get_random_bytes(8),
            iv: vec![0; 0],
            key: vec![0; 0],
        }
    }
}

impl OpensslEncrypt {
    fn get_random_bytes(length: usize) -> Vec<u8> {
        let mut buf = vec![0; length];
        rand_bytes(&mut buf).unwrap();
        return buf;
    }
    pub fn encrypt(mut self, chunk: Vec<u8>) -> Vec<u8> {
        if self.key.len() == 0 {
            println!("key doesnt exist creating values...");
            let iterations = NonZeroU32::new(10000).unwrap();
            let mut pbkdf2_key_iv = [0; 48]; // 256 bits + 128 bits
            
            pbkdf2::derive(PBKDF2_ALG, iterations,  &self.salt, &self.password, &mut pbkdf2_key_iv);

            self.key = pbkdf2_key_iv[0..32].to_vec(); // 256 bits
            self.iv = pbkdf2_key_iv[32..48].to_vec(); // 128 bits
        }
        let magic_header = &["Salted__".as_bytes(), &self.salt].concat();

        // REMOVE ME
        println!("{:x?}", self.salt.iter());
        println!("{:x?}", self.key.iter());
        println!("{:x?}", self.iv.iter());

        let mut encrypter = Crypter::new(
            Cipher::aes_256_cbc(),
            Mode::Encrypt,
            &self.key,
            Some(&self.iv)).unwrap();

        let block_size = Cipher::aes_256_cbc().block_size();
        let mut ciphertext = vec![0; chunk.len() + block_size];

        let mut count = encrypter.update(&chunk, &mut ciphertext).unwrap();
        count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);

        return [&magic_header[..], &ciphertext[..]].concat();
    }
}
