extern crate openssl;

use openssl::symm::{encrypt, decrypt, Cipher, Crypter, Mode};
use rand::Rng;
use std::str;

fn generate_aes_key() -> Vec<u8> {

    let mut rng = rand::thread_rng();
    let mut k = Vec::with_capacity(16);

    for _j in 0..16 {

        let x: u8 = rng.gen();
        k.push(x)
    }

    return k;
}

// append 5-10 random bytes before and after text
fn append_rand_bytes(text: &[u8]) -> Vec<u8> {
    
    let mut chal_pad = Vec::with_capacity(text.len() + 20);
    
    let before:i32 = rand::thread_rng().gen_range(5, 11);
    for _x in 0..before{
        
        let b:u8 = rand::thread_rng().gen_range(0, 255);
        chal_pad.push(b);
    }
    
    for (_i, j) in text.iter().enumerate() {
        
        chal_pad.push(*j);
    }

    let after:i32 = rand::thread_rng().gen_range(5, 11);
    for _x in 0..after{
        
        let b:u8 = rand::thread_rng().gen_range(0, 255);
        chal_pad.push(b);
    }

    return chal_pad;
}

fn encrypt_at_random(text: &[u8]) -> Vec<u8> {

    let key = generate_aes_key();
    let iv = generate_aes_key(); // also should be 16 rand bytes

    let choice:bool = rand::thread_rng().gen();
    if choice {

        let cipher = Cipher::aes_128_ecb();
        let ecb = encrypt(cipher, &key, None, text).unwrap();
        let padded = append_rand_bytes(&ecb);

        println!("ECB"); // hint to tell if oracle works.
        return padded;
    } else {

        let cipher = Cipher::aes_128_cbc();
        let cbc = encrypt(cipher, &key, Some(&iv), text).unwrap();
        let padded = append_rand_bytes(&cbc);
        
        println!("CBC"); // hint to tell if oracle works.
        return padded;
    }
}

// oracle
fn is_aes_ecb(text: &[u8]) -> bool {
        
    for (i, _j) in text.iter().enumerate() {
        if i + 32<= text.len(){

            let mut block1: Vec<&u8> = Vec::with_capacity(16);
            for x in 0..16{
                block1.push(&text[i + x]);
            }
            let mut block2: Vec<&u8> = Vec::with_capacity(16);
            for x in 0..16{
                block2.push(&text[i + (x + 16)]);
            }

            if block1 == block2{
                return true;
            }
        }
    }

    return false;
}

fn main() {
    
    let plaintext = "ddddddddddddddddddddddddddddddddddddd".as_bytes();
    
    // test len > 32 
    // wont work without 2 16 byte blocks to compare
    if plaintext.len() < 32 {

        println!("Insufficient bytes to determine if AES ECB mode.");
    }

    println!("Ciphertext is ECB: {}", is_aes_ecb(&encrypt_at_random(plaintext)));
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_is_aes_ecb(){
        
        // baselining
        let c1: [u8; 3] = [1, 2, 3];
        let c2: [u8; 3] = [1, 2, 3];
        assert_eq!(c1, c2);
        let mut c3 = "abcdefghijklmnopqrstuvwxyz1234567890".as_bytes();
        assert_eq!(false, is_aes_ecb(c3));
        c3 = "tttttttttttttttttttttttttttttttttttt".as_bytes();
        assert_eq!(true, is_aes_ecb(c3));
        c3 = "abcvdefgttttttttt88888888999999777777".as_bytes();
        assert_eq!(false, is_aes_ecb(c3));
        c3 = "abcdefmoonlionfishtwigmoonlionfishtwigghijklm".as_bytes();
        assert_eq!(true, is_aes_ecb(c3));

        // encrypted test
        let plaintext = "ttttttttttttttttttttttttttttttttttttttttttt".as_bytes();
        for _  in 0..100{
            
            println!("Is ECB: {}\n", is_aes_ecb(&encrypt_at_random(plaintext)));
        }
    }

    #[test]
    fn test_append_rand_bytes(){

        let text = "Tag team, back again, check it's a record".as_bytes();
        println!("Text: {:?}", text);

        let apptext = append_rand_bytes(&text);
        println!("Text: {:?}", apptext);
    }

    #[test]
    fn test_encrypt_decrypt(){

        // ecb
        let cipher = Cipher::aes_128_ecb();
        let txt = b"She turned me into a newt!";
        let key = b"I got better....";

        let encrypted = encrypt(cipher, key, None, txt).unwrap();
        println!("encrypted: {:?}", encrypted);
        println!("encrypted len: {}", encrypted.len());

        let decrypted = decrypt(cipher, key, None, &encrypted).unwrap();
        println!("Decrypted: {:?}", decrypted);
        println!("Decrypted len: {}", decrypted.len());
        println!("Returned: {}", str::from_utf8(&decrypted).unwrap());

        // cbc
        let cbc_cipher = Cipher::aes_128_cbc();
        let cbc_txt = "All right! Stop whatcha doin' 'cause I'm about to ruin'".as_bytes();
        let cbc_key = b"Now gather round";
        let cbc_iv = b"I like to rhyme!";

        let enc = encrypt(cbc_cipher, cbc_key, Some(cbc_iv), cbc_txt).unwrap();
        println!("encrypted: {:?}", enc);
        println!("encrypted len: {}", enc.len());

        // decrypt api is choking.  Unclear why.  
        // Manual implementation of Crypter
        let mut dcpt = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, cbc_key, Some(cbc_iv)).unwrap();
        let mut out = vec![0 as u8; cbc_txt.len() + Cipher::aes_128_cbc().block_size() * 2];
        let _dec = dcpt.update(&enc, &mut out).unwrap();
        out.truncate(cbc_txt.len());

        println!("Decryted: {:?}", out);
        println!("Decryted: {}", str::from_utf8(&out).unwrap());
        println!("Decrypted len: {}", out.len());
        assert_eq!(out, cbc_txt);
    }  

    #[test]
    fn test_generate_key() {
        
        // must load vector/array with 16 random bytes
        for _j in 0..10 {
            
            let key = generate_aes_key();
            assert_eq!(key.len(), 16);
            println!("generated key: {:?}", key);
        }
    }

    #[test]
    fn test_50_50() {
        
        // generates a 0 or 1.
        for _j in 0..100{
            let num = rand::thread_rng().gen_range(0, 2);
            println!{"{}", num}
        }

    }
    
    #[test]
    fn test_encrypt_at_random(){

        let txt = "Tag team, back again, check it's a record, let's begin...".as_bytes();
        for _j in 0..10{
            let x = encrypt_at_random(txt);
            println!("{:?}", x);
            println!("{}\n", x.len())
        }
    }
}   
