use openssl::symm::{Cipher, Mode, Crypter};
use openssl::rand::rand_bytes;
use crypto::pbkdf2::pbkdf2_simple;
use crypto::sha2::Sha256;
use crypto::hmac::Hmac;
use std::io::{self, BufReader};
use std::io::prelude::*;
use std::fs::File;

static ONE_KB: u64 = 1024;

fn main() {

    let max_buffer_size = ONE_KB;
    let mut file_chunk_buf = vec![0u8; max_buffer_size as usize];

    let mut file = File::open("test.txt").unwrap();

    let file_metadata = file.metadata().unwrap();
    let file_length = file_metadata.len();

    file.read_exact(&mut file_chunk_buf).unwrap();

    let mut key = [0; 256];
    let mut iv = [0; 256];
    let mut salt = [0; 64];
   // let mut pbkdf2_key = [0; 256];
    rand_bytes(&mut key).unwrap();
    rand_bytes(&mut iv).unwrap();
    rand_bytes(&mut salt).unwrap();

    let mut mac = Hmac::new(Sha256::new(), "password".as_bytes());

    //pbkdf2(&mut mac, &salt, 1, &mut pbkdf2_key);



    let pbkdf2_key = pbkdf2_simple("password", 2048).unwrap();
    println!("{:?}", pbkdf2_key.as_bytes());

   // let plaintexts: [&[u8]; 2] = [b"Some Stream of", b" Crypto Text"];
    let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
   // let data_len = plaintexts.iter().fold(0, |sum, x| sum + x.len());

   // let file = File::open("test.txt").unwrap();
    //file.read_exact(&mut vector_buffer).unwrap();

    // Create a cipher context for encryption.
    let mut encrypter = Crypter::new(
        Cipher::aes_256_cbc(),
        Mode::Encrypt,
        pbkdf2_key.as_bytes(),
        Some(iv)).unwrap();

    let block_size = Cipher::aes_256_cbc().block_size();
    let mut ciphertext = vec![0; file_length as usize + block_size];

    // Encrypt 2 chunks of plaintexts successively.
    let mut count = encrypter.update(&file_chunk_buf, &mut ciphertext).unwrap();
   // count += encrypter.update(plaintexts[1], &mut ciphertext[count..]).unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);

     let mut out_file = File::create("out.enc").unwrap();
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
