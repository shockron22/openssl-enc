# openssl_enc

An Implementation of openssl enc functionality.

This library encrypts and decrypts just like openssl enc on the command line.
Allowing you to encrypt with this library and then decrypt with openssl on the other end. or vice versa.

This library supports encrypting/decrypting whole data all at once or a chunk at a time. 

## Examples

Encrypt data in chunks

```rust
    use std::fs::File;
    use std::io::prelude::*;
    use openssl::symm::Cipher;
    use openssl_enc::OpensslEnc;

    let mut file_chunk_buf = vec![0u8; 1024];
    let mut file = File::open("test.txt").unwrap();
    let mut out_file = File::create("out.enc").unwrap();
    let mut openssl_encrypt = OpensslEnc::new("password".to_string(), Cipher::aes_256_cbc(), 10000).unwrap();

    loop {
      let bytes_read = file.read(&mut file_chunk_buf).unwrap();
      file_chunk_buf.truncate(bytes_read);
      if bytes_read == 0 {
        break;
      }
      let encrypted_data = openssl_encrypt.encrypt_chunk(&mut file_chunk_buf).unwrap();
      out_file.write(&encrypted_data).unwrap();
    }
    let final_data = openssl_encrypt.encrypter_finalize().unwrap();
    out_file.write(&final_data).unwrap();
    out_file.flush().unwrap();
```

 Then outside of this to decrypt with openssl you can run.
 ```bash
  openssl enc -p -d -aes-256-cbc -md SHA256 -pbkdf2 -iter 10000 -in out.enc -out out.txt
 ```

see the cargo docs for in depth explanation. 
