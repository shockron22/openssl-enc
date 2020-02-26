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
    pub iteration_count: u32,
}

impl Default for OpensslEncrypt {
    fn default() -> OpensslEncrypt {
        return OpensslEncrypt {
            password: OpensslEncrypt::get_random_bytes(50),
            salt: OpensslEncrypt::get_random_bytes(8),
            iv: vec![0; 0],
            key: vec![0; 0],
            iteration_count: 10000,
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
            let iterations = NonZeroU32::new(self.iteration_count).unwrap();
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

    pub fn decrypt(mut self, chunk: Vec<u8>) -> Vec<u8> {
        /*// Let's pretend we don't know the plaintext, and now decrypt the ciphertext.
        let data_len = ciphertext.len();
        let ciphertexts = [&ciphertext[..9], &ciphertext[9..]];

        // Create a cipher context for decryption.
        let mut decrypter = Crypter::new(
            Cipher::aes_128_cbc(),
            Mode::Decrypt,
            key,
            Some(iv)).unwrap();
        let mut plaintext = vec![0; data_len + block_size];

        // Decrypt 2 chunks of ciphertexts successively.
        let mut count = decrypter.update(ciphertexts[0], &mut plaintext).unwrap();
        count += decrypter.update(ciphertexts[1], &mut plaintext[count..]).unwrap();
        count += decrypter.finalize(&mut plaintext[count..]).unwrap();
        plaintext.truncate(count);

        let mut out_file = File::create("out.txt").unwrap();
        out_file.write(&plaintext).unwrap();
        out_file.flush().unwrap();
        //assert_eq!(b"Some Stream of Crypto Text", &plaintext[..]);*/
    }
}
