use std::io::prelude::*;
use std::fs::File;

mod openssl_encrypt;

use openssl_encrypt::OpensslEncrypt;
use openssl::symm::{Cipher};

static ONE_KB: usize = 1024;

fn main() {

    let max_buffer_size = ONE_KB;
    let mut file_chunk_buf = vec![0u8; max_buffer_size as usize];

    let mut file = File::open("test.txt").unwrap();

    let file_metadata = file.metadata().unwrap();
    let _file_length = file_metadata.len();

    
    let mut out_file = File::create("out.enc").unwrap();
    
    let mut openssl_enc = OpensslEncrypt::new("password".to_string(), Cipher::aes_256_cbc(), 10000);

    // let mut out_file2 = File::create("out2.txt").unwrap();

    loop {
      let bytes_read = file.read(&mut file_chunk_buf).unwrap(); // this is going to cause random null characters. 
      file_chunk_buf.truncate(bytes_read);
      if bytes_read == 0 {
        break;
      }
      //file_chunk_buf.retain(|&i|i != 0);
      let encrypted_data = openssl_enc.encrypt_chunk(&mut file_chunk_buf);
      out_file.write(&encrypted_data).unwrap();
    }
    println!("finalize");
    let final_data = openssl_enc.encrypter_finalize();
    out_file.write(&final_data).unwrap();
    out_file.flush().unwrap();

    let mut enc_out_file = File::open("out.enc").unwrap();
    let mut file_chunk_buf2 = vec![0u8; 100000000];
    enc_out_file.read_to_end(&mut file_chunk_buf2);
    let decrypted = openssl_enc.decrypt(file_chunk_buf2);
    let mut out_file2 = File::create("out2.txt").unwrap();
    out_file2.write(&decrypted).unwrap();


   // let plaintext_data = openssl_enc.decrypt(encrypted_data);
   // out_file2.write(&plaintext_data).unwrap();
   // out_file2.flush().unwrap();



/*
   loop {
      let bytes_read = file.read(&mut file_chunk_buf).unwrap();

      if bytes_read == 0 {
        break;
      }

      let out_text: Vec<u8> = openssl_encrypt.encrypt_chunk(&file_chunk_buf);
      out_file.write(out_text.as_ref()).unwrap();
      out_file.flush().unwrap();
    }
    let final_block: Vec<u8> = openssl_encrypt.finalize();
    out_file.write(final_block.as_ref()).unwrap();
    out_file.flush().unwrap();

    let mut whole_file = vec![0u8; max_buffer_size * 2];
    let bytes_read = file.read(&mut whole_file).unwrap();
    println!("whole file bytes read: {}", bytes_read);
    println!("{:?}", whole_file);
    let decrypted_data = openssl_encrypt.decrypt(whole_file);
    out_file3.write(&decrypted_data).unwrap();
    out_file3.flush().unwrap();*/
}
