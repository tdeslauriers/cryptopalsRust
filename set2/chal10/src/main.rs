extern crate utils;
extern crate base64;

use std::str;
use std::fs;

fn main() {

    let mut iv = vec![0u8; 16]; 
    let key = b"YELLOW SUBMARINE"; 
    
    let file = fs::read_to_string("./src/ch10.txt").expect("Failed to read file.");
    let cipher_bytes = base64::decode(file).unwrap();

    let mut plaintext = Vec::new();
    let mut counter = 0;
    for _x in 0..cipher_bytes.len()/key.len(){

        let block = &cipher_bytes[counter..counter + key.len()];
        let decrypted_block = utils::aes128_ecb_decrypt(block, key);
        let xor_decrypted_block = utils::xor_with_key(&decrypted_block, &iv);

        for (_i, j) in xor_decrypted_block.iter().enumerate(){
            
            plaintext.push(*j);
        }
        
        for (i, j) in block.iter().enumerate(){

            iv[i] = *j;
        }

        counter += key.len();
    }

    println!("{}", str::from_utf8(&plaintext).unwrap());
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_single_block_impl() {
        
        let plaintext = b"testBearMaceLive";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let key = b"needsToBeSixteen"; // aes128 takes 16 char key

        let mut xor_text = utils::xor_with_key(plaintext, iv);
        println!("plaintext: {:?}", plaintext);
        println!("xor: {:?}", xor_text);

        let ciphertext = utils::aes128_ecb_encrypt(&xor_text, key);
        println!("ciphertext: {:?}", ciphertext);
        let ciphertext_clipped = &ciphertext[0..key.len()];

        // decrypt
        xor_text = utils::aes128_ecb_decrypt(&ciphertext_clipped, key);
        let re_plaintext = utils::xor_with_key(&xor_text, iv);
        println!("plaintext back: {:?}", re_plaintext);
    }    

    #[test]
    fn test_cbc_impl() {
        
        let plaintext = "If it is brown, lay down.  If it is black, go on the attack".as_bytes();
        let mut iv = *b"testBearMaceLive"; // iv needs to matche key size = 16 chars
        let key = b"needsToBeSixteen"; // aes128 takes 16 char key

        let padded = utils::pad(plaintext, key);
        println!("Padded: {:?}", padded);
        
        let mut ciphertext = Vec::new();
        let mut counter = 0;
        for x in 0..padded.len()/key.len(){

            let block = &padded[counter..counter + key.len()];
            let xor_text = utils::xor_with_key(block, &iv);
            let cipher = utils::aes128_ecb_encrypt(&xor_text, key);
            
            for (i, x) in cipher.iter().enumerate() {
                iv[i] = *x;
                ciphertext.push(*x);
            }

            println!("block {}: {:?}", x, block);
            println!("xor {}: {:?}", x, xor_text);
            println!("cipher {}: {:?}", x, &cipher);
            println!("new iv {}: {:?}\n", x, iv);
            
            counter += key.len();
        }

        println!("cipher text: {:?}", ciphertext);
        let b64 = base64::encode(ciphertext);
        println!("output: {}", b64);
    }

    #[test]
    fn test_cbc_decrypt() {
        
        // from above test
        let plaintext_original = "If it is brown, lay down.  If it is black, go on the attack".as_bytes();
        let mut iv = *b"testBearMaceLive"; // iv needs to matche key size = 16 chars
        let key = b"needsToBeSixteen"; // aes128 takes 16 char key

        let mut plaintext = Vec::new();
        let cipher = base64::decode("OdZAliURqm5Q8TWMsOx8z4H8Rbas7xDT8Ptk9c3ezeLGApfIldyxzLWvSJU77Ln1StsQh2/Cif9q658anTKULUqAM0EH29Vwgc95JvcrmEs=").unwrap();
        let mut counter = 0;     
        for x in 0..cipher.len()/key.len() {
            let block = &cipher[counter..counter + key.len()];     
            let plain = utils::aes128_ecb_decrypt(block, key);
            println!("plain {}: {:?}", x, plain);
            println!("iv {}: {:?}", x, iv);
            let xor_text = utils::xor_with_key(&plain, &iv);
            println!("de-xor {}: {:?}", x, xor_text);

            for (i, x) in block.iter().enumerate() {
                
                iv[i] = *x;
            }
            println!("new iv {}: {:?}\n", x, iv);

            for (_i, x) in xor_text.iter().enumerate() {
                plaintext.push(*x);
            }

            counter += key.len();
        } 
        
        println!("Plain orig: {:?}", plaintext_original);
        println!("Plain back: {:?}", plaintext);
        println!("text: {}", str::from_utf8(&plaintext).unwrap());
        
    }
}