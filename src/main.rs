use openssl::symm::{Cipher, Mode, Crypter};
use openssl::rand::rand_bytes;
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use std::io::prelude::*;
use std::fs::File;

use ring::{pbkdf2};
use std::{num::NonZeroU32};

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static ONE_KB: u64 = 1024;

fn main() {

    let max_buffer_size = ONE_KB;
    let mut file_chunk_buf = vec![0u8; max_buffer_size as usize];

    let mut file = File::open("test.txt").unwrap();

    let file_metadata = file.metadata().unwrap();
    let file_length = file_metadata.len();

    file.read_exact(&mut file_chunk_buf).unwrap();

    let mut pbkdf2_key = [0; 32]; // 256 bits
    let mut iv = [0; 16]; // 128 bits
    let mut salt = [0; 8]; // 64 bits
    rand_bytes(&mut iv).unwrap();
    rand_bytes(&mut salt).unwrap();
    rand_bytes(&mut pbkdf2_key).unwrap();

    println!("{:x?}", salt.iter());
    println!("{:x?}", pbkdf2_key.iter());
    println!("{:x?}", iv.iter());

    let iterations = NonZeroU32::new(1).unwrap();

    pbkdf2::derive(PBKDF2_ALG, iterations,  &salt, "password".as_bytes(), &mut pbkdf2_key);

   // let plaintexts: [&[u8]; 2] = [b"Some Stream of", b" Crypto Text"];
   // let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
   // let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
  let key = b"\x4F\x61\x09\x9E\xC1\xD8\x22\x75\x1F\x1B\x4B\x03\x79\x05\x24\x10\xCE\xE1\x8F\x74\x81\x15\x0F\x18\x0D\x73\x10\x5C\x13\x2F\xB1\xD3";
  let iv = b"\x78\x54\xF6\x1F\xBC\x2E\xF1\xAA\xA5\x9A\x32\x01\x34\x8B\x2E\x7E";
  let salt = b"\x8B\x8C\xD9\xD4\xBD\xC8\x0D\xD0";
  let magic_header = ["Salted__".as_bytes(), salt].concat();

   // let data_len = plaintexts.iter().fold(0, |sum, x| sum + x.len());

   // let file = File::open("test.txt").unwrap();
    //file.read_exact(&mut vector_buffer).unwrap();

    // Create a cipher context for encryption.
    let mut encrypter = Crypter::new(
        Cipher::aes_256_cbc(),
        Mode::Encrypt,
        key,
        Some(iv)).unwrap();

    let block_size = Cipher::aes_256_cbc().block_size();
    let mut ciphertext = vec![0; file_length as usize + block_size];

    // Encrypt 2 chunks of plaintexts successively.
    let mut count = encrypter.update(&file_chunk_buf, &mut ciphertext).unwrap();
   // count += encrypter.update(plaintexts[1], &mut ciphertext[count..]).unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);

     let mut out_file = File::create("out.enc").unwrap();
     out_file.write(&magic_header).unwrap();
     out_file.write(&ciphertext).unwrap();
     out_file.flush().unwrap();


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
