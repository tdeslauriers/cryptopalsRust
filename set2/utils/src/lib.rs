extern crate base64;
extern crate openssl;

use openssl::symm::{Cipher, encrypt, decrypt};
use std::str;

// functions needed across multiple challenges

pub fn xor_with_key(text: &[u8], key: &[u8]) -> Vec<u8> {

    let mut r = Vec::with_capacity(text.len());
    let mut count = 0;
    for j in text{
        
        let ciph = j ^ key[count];
        r.push(ciph);
        if count == key.len()-1 {
            count = 0;
        } else {
            count += 1;
        }
    }
    return r;
}

pub fn pad(text: &[u8], key: &[u8]) -> Vec<u8> {

    if text.len() < 1 {
        println!("Invalid text length: {}", text.len());
    }
    if key.len() < 1 {
        println!("Invalid key length: {}", key.len());
    }

    let r = text.len() % key.len();

    let mut padded = Vec::with_capacity(text.len() + r + key.len()); 
    for x in 0..text.len(){
        padded.push(text[x]);
    }

    if r != 0 {

        let padlen = key.len() - r;
        for _x in 0..padlen {
            padded.push(padlen as u8);
        }
    }

    for _x in 0..key.len(){
        padded.push(key.len() as u8)
    }
    
    return padded;
}

pub fn aes128_ecb_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    
    let ciphertext = encrypt(Cipher::aes_128_ecb(), key, None, plaintext).unwrap();
    return ciphertext;
}

pub fn aes128_ecb_decrypt(ciphertext: &[u8], key: &[u8]) ->Vec<u8>{

    let plaintext = decrypt(Cipher::aes_128_ecb(), key, None, ciphertext).unwrap();
    return plaintext;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitwise_xor(){

        let b1:u8 = b't';
        let b2:u8 = b'd';
        let xb:u8 = b1 ^ b2;
        println!("Bitwise ^ starting vals: {}, {}", b1, b2);
        println!("Bitwise ^: {}", xb);
        assert_eq!(b1, xb ^ b2);
        println!("Re-XOr'd: {}", xb ^ b2);
    }

    #[test]
    fn test_xor_with_key() {
        
        let mut txt = "dog".as_bytes();
        let mut key = "key".as_bytes();
        let mut xor = xor_with_key(txt, key);
        assert_eq!(xor, [15, 10, 30]);
        assert_eq!(xor_with_key(&xor[..], key), txt);
        
        txt = "monkey".as_bytes();
        key = "key".as_bytes();
        xor = xor_with_key(txt, key);
        assert_eq!(xor, [6, 10, 23, 0, 0, 0]);
        assert_eq!(xor_with_key(&xor[..], key), txt);

        txt = "bear".as_bytes();
        key = "key".as_bytes();
        xor = xor_with_key(txt, key);
        assert_eq!(xor, [9, 0, 24, 25]);
        assert_eq!(xor_with_key(&xor[..], key), txt);
        
        txt = "lion".as_bytes();
        key = "hyena".as_bytes();
        xor = xor_with_key(txt, key);
        assert_eq!(xor, [4, 16, 10, 0]);
        assert_eq!(xor_with_key(&xor[..], key), txt);
    }

    #[test]
    fn test_base64() {
        
        let b64 = base64::encode(b"X gon' give it to ya");
        println!("{}", b64);

        let bytes = base64::decode("WCBnb24nIGdpdmUgaXQgdG8geWE=").unwrap();
        println!("{}", str::from_utf8(&bytes).unwrap());
    }

    #[test]
    fn test_pad() {
        
        let text = b"tiger";
        let key = b"cat";
        let padded = pad(text, key);
        assert_eq!(padded.len(), 9);
        assert_eq!(padded[5], 1);
        assert_eq!(padded[8], 3);

        let text = b"tigers";
        let key = b"cat";
        let padded = pad(text, key);
        assert_eq!(padded.len(), 9);
        assert_eq!(padded[7], 3);

        let text = b"cat";
        let key = b"tiger";
        let padded = pad(text, key);
        assert_eq!(padded.len(), 10);
        assert_eq!(padded[6], 5);
        assert_eq!(padded[3], 2);
    }

    #[test]
    fn test_aes128() {
        
        let data = b"Lions have big teeth";
        let key = b"needsToBeSixteen"; // aes128 takes 16 char key
        let ciphertext = aes128_ecb_encrypt(data, key);

        println!("{:?}", ciphertext);
        assert_eq!(240, ciphertext[1]);
        assert_eq!(254, ciphertext[8]);

        let plaintext = aes128_ecb_decrypt(ciphertext.as_slice(), key);
        println!("data: {:?}", data);
        println!("plain: {:?}", plaintext);
        assert_eq!(data, plaintext.as_slice());
        println!("{}", str::from_utf8(&plaintext).unwrap())
    }

}
