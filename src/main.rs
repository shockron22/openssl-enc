use std::io::prelude::*;
use std::fs::File;

mod openssl_encrypt;

static ONE_KB: usize = 1024;

fn main() {

    let max_buffer_size = ONE_KB;
    let mut file_chunk_buf = vec![0u8; max_buffer_size as usize];

    let mut file = File::open("test.txt").unwrap();

    let file_metadata = file.metadata().unwrap();
    let file_length = file_metadata.len();

    file.read_exact(&mut file_chunk_buf).unwrap();


    let mut out_file = File::create("out.enc").unwrap();

      file.read_exact(&mut file_chunk_buf).unwrap();

      // encrypt here

        let openssl_encrypt = openssl_encrypt::OpensslEncrypt { 
          password: "password".as_bytes().to_vec(),
          ..Default::default() 
        };

        let out_text: Vec<u8> = openssl_encrypt.encrypt(file_chunk_buf);
     //   println!("{:?}", out_text.iter());

      out_file.write(out_text.as_ref()).unwrap();
      out_file.flush().unwrap();
    
}
