

use openssl::symm::{encrypt, Cipher, decrypt}; // decrypt needed by tests
use std::str;
use base64::decode;
use rand::Rng;

//challenge text
const CHALTEXT: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

// space "character" included at the end
// new line "character" included in bytes dic" 
const DICTIONARY: &[u8] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\n,.?!'-=+*&^%$#@!() ".as_bytes(); 

fn main() {
    
    let chal_txt = decode(CHALTEXT).unwrap();
    let key = generate_random_key();

    let blocksize = get_block_size(b"ddd", &key);
    let mut feeder: Vec<u8> = Vec::with_capacity(blocksize * 2);
    for _i in 0..(blocksize * 2){
        feeder.push(b"d"[0])
    }

    let is_aes_ecb_128 = detect_ecb_128(&encrypt_ecb_128(&feeder, &key), blocksize);

    let pad_length = blocksize - (chal_txt.len() % blocksize);
    let mut padded: Vec<u8> = Vec::with_capacity(chal_txt.len()+pad_length);
    for i in chal_txt.iter(){
        padded.push(*i)
    }
    for _j in 0..pad_length{
        padded.push(b"p"[0])
    }
        
    let mut plain_text_bytes: Vec<u8> = Vec::with_capacity(padded.len());
    
    if is_aes_ecb_128 {

        for i in (0..padded.len()).step_by(blocksize) {

            let cracked = crack_block(&padded[i..i+blocksize], DICTIONARY, &key);
            for j in cracked.iter() {
                plain_text_bytes.push(*j);
            }
        }
    }
    println!("Penguins: {}", str::from_utf8(&plain_text_bytes[0..padded.len()-pad_length]).unwrap())
}

fn generate_random_key() -> Vec<u8> {

    let mut rng = rand::thread_rng();
    let mut key = Vec::with_capacity(16);

    for _x in 0..16 {
         
        let y: u8 = rng.gen();
        key.push(y);
    }

    return key;
}

fn encrypt_ecb_128(text: &[u8], key: &[u8]) -> Vec<u8>{

    let cipher = Cipher::aes_128_ecb();
    let ecb = encrypt(cipher, &key, None, text).unwrap();

    return ecb;
}

fn get_block_size(text: &[u8], key: &[u8]) -> usize {

    // can get block size by encrypting a short string
    return encrypt_ecb_128(&text, &key).len();
}

fn detect_ecb_128(ciph: &[u8], blocksize: usize) -> bool{

    for i in 0..(blocksize * 2){
        
        let mut b1: Vec<u8> = Vec::with_capacity(blocksize);
        for j in 0..blocksize {
            b1.push(ciph[i + j]);
        }
        let mut b2: Vec<u8> = Vec::with_capacity(blocksize);
        for k in 0..blocksize {
            b2.push(ciph[i + (k + blocksize)]);
        }

        if b1 == b2 {
            return true
        }
    }
    return false
}

fn brute_force_last_byte(block: &[u8], dic: &[u8], key: &[u8]) -> Result<u8, String> {
    
    let val = encrypt_ecb_128(&block, key);
    
    // create brute forcing dictionary
    let mut brute_force_dic: Vec<Vec<u8>> = Vec::with_capacity(dic.len());
    for i in 0..dic.len(){
        let mut bf_val: Vec<u8> = Vec::with_capacity(block.len()); 
        for j in 0..block.len() - 1{
            bf_val.push(block[j])
        }
        bf_val.push(dic[i]);
        brute_force_dic.push(encrypt_ecb_128(&bf_val, key));
    }

    // compare crack value to all vals in brute force dictionary
    for i in 0..brute_force_dic.len(){
        if brute_force_dic[i][0..16] == val[0..16] {
             return Ok(dic[i]);
        } 
    }
    
    return Err("No match for byte in brute force library".to_string())
}

fn crack_block(block: &[u8], dic: &[u8], key: &[u8]) -> Vec<u8> {

    // seed 
    let same_byte:u8 = 100; //byte code for "d"
    let mut seed_counter = 1;
    
    // bucket for cracked bytes
    let mut result: Vec<u8> = Vec::with_capacity(block.len());
    
    // loop thru cracking bytes of chanllenge block
    for _i in 0..block.len(){
        
        let mut seed: Vec<u8> = Vec::with_capacity(block.len());
        for _j in 0..block.len() - seed_counter {
            seed.push(same_byte)
        }

        for k in 0..seed_counter {
            seed.push(block[k])
        }

        result.push(brute_force_last_byte(&seed, dic, key).unwrap());
        seed_counter += 1;
    }
    return result;
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_multiple_blocks() {
        
        // dry run with known values
        let chal_txt = decode(CHALTEXT).unwrap();
        let key = generate_random_key();

        let blocksize = get_block_size(b"ddd", &key);
        let mut feeder: Vec<u8> = Vec::with_capacity(blocksize * 2);
        for _i in 0..(blocksize * 2){
            feeder.push(b"d"[0])
        }

        let is_aes_ecb_128 = detect_ecb_128(&encrypt_ecb_128(&feeder, &key), blocksize);

        let pad_length = blocksize - (chal_txt.len() % blocksize);
        let mut padded: Vec<u8> = Vec::with_capacity(chal_txt.len()+pad_length);
        for i in chal_txt.iter(){
            padded.push(*i)
        }
        for _j in 0..pad_length{
            padded.push(b"p"[0])
        }
            
        let mut plain_text_bytes: Vec<u8> = Vec::with_capacity(padded.len());
        
        if is_aes_ecb_128 {

            for i in (0..padded.len()).step_by(blocksize) {

                let cracked = crack_block(&padded[i..i+blocksize], DICTIONARY, &key);
                for j in cracked.iter() {
                    plain_text_bytes.push(*j);
                }
            }
        }
        println!("Penguins: {}", str::from_utf8(&plain_text_bytes[0..padded.len()-pad_length]).unwrap())

    }

    #[test]
    fn test_crack_block() {
        let key = b"yippieOyippieYay";
        let chal = b"Atomic Dooooooog";

        let cracked_byte = crack_block(chal, DICTIONARY, key);
        println!("{:?}\n{:?}\n", chal, cracked_byte);
        println!("{}", str::from_utf8(&cracked_byte).unwrap());
        assert_eq!(chal[0..chal.len()], cracked_byte[0..cracked_byte.len()])
    }

    #[test]
    fn test_brute_force_last_byte() {
        
        let key = b"yippieOyippieYay";
        let seed = b"dddddddddddddddt";

        println!("{:?}", brute_force_last_byte(seed, DICTIONARY, key).ok().unwrap() as char);
        assert_eq!(b"t"[0], brute_force_last_byte(seed, DICTIONARY, key).ok().unwrap())
    }

    #[test]
    fn test_byte_discovery() {

        let test_key = b"tttttttttttttttt";
        let seed = b"ddddddddddddddd";

        let mut brute_force_dic: Vec<Vec<u8>> = Vec::with_capacity(DICTIONARY.len());
        for i in 0..DICTIONARY.len() {
            let mut bf_try: Vec<u8> = Vec::with_capacity(16);
            for j in 0..seed.len() {
                bf_try.push(seed[j]);
            }
            bf_try.push(DICTIONARY[i]);
            brute_force_dic.push(bf_try);
        }
        
        let chal = decode(CHALTEXT).unwrap();
        let mut padded: Vec<u8> = Vec::with_capacity(chal.len() + 16);
        for i in seed.iter(){
            padded.push(*i);
        }
        for i in 0..chal.len(){
            padded.push(chal[i]);
        }
        // raw input compare
        for (i, j) in brute_force_dic.iter().enumerate(){

            if *j == &padded[0..16]{
                println!("padded: {:?} = brute: {:?}\n", &padded[0..16], j);
                println!("Which corresponds to {} in dic", DICTIONARY[i] as char);
            }
        }
        // encrypted input compare
        let enc = encrypt_ecb_128(&padded, test_key);
        let mut enc_brute_force_dic: Vec<Vec<u8>> = Vec::with_capacity(brute_force_dic.len());
        for i in brute_force_dic.iter(){
            enc_brute_force_dic.push(encrypt_ecb_128(i, test_key))
        }
        for (i, j) in enc_brute_force_dic.iter().enumerate(){

            if j[0..16] == enc[0..16]{
                println!("enc {:?} = enc_brute: {:?}\n", &enc[0..16], j);
                println!("Which corresponds to {} in dic", DICTIONARY[i] as char);
            }
        }


    }

    // must detect function is using EBC
    #[test]
    fn test_detect_ecb_128() {
        
        let txt: &[u8; 32] = b"dddddddddddddddddddddddddddddddd";
        let ciph = encrypt_ecb_128(txt, &generate_random_key());
        assert_eq!(detect_ecb_128(&ciph, 16), true)
    }

    // must be able to determine block size of encrypted text
    // Feed identical bytes of your-string to the function 1 at a time --- 
    // start with 1 byte ("A"), then "AA", then "AAA" and so on. 
    // Discover the block size of the cipher. You know it, but do this step anyway.
    #[test]
    fn test_find_block_size(){

        let mut vals: Vec<Vec<u8>> = Vec::with_capacity(16);
        let key = generate_random_key();
        let mut encrypted = encrypt_ecb_128(b"t", &key);
        vals.push(encrypted);
        encrypted = encrypt_ecb_128(b"tt", &key);
        vals.push(encrypted);
        encrypted = encrypt_ecb_128(b"ttt", &key);
        vals.push(encrypted);
        encrypted = encrypt_ecb_128(b"tttt", &key);
        vals.push(encrypted);
        for x in vals{
            assert_eq!(x.len(), 16);  
        }
        let test_block = get_block_size(b"Atomic doc", &key );
        assert_eq!(test_block, 16)
    }

    // must encrypt (MYSTRING +(append) CHALLTEXT) with AES_128_EBC using random key
    #[test]
    fn test_encrypt_ecb_128() {
        let key = b"bowWowWowYippieO";
        let text = b"why must I be like that Why must"; // 24 bytes

        let mut encrypted = encrypt_ecb_128(text, key); // output is 32 byte => padded
        println!("{:?}", encrypted);
        println!("Encrypted text length: {}", encrypted.len());

        let cipher = Cipher::aes_128_ecb();
        let mut decrypted = decrypt(cipher, key, None, &encrypted).unwrap();
        for i in 0..text.len(){
            assert_eq!(text[i], decrypted[i])
        }

        let rand_key = generate_random_key();
        encrypted = encrypt_ecb_128(text, &rand_key);
        decrypted = decrypt(cipher, &rand_key, None, &encrypted).unwrap();
        for i in 0..text.len(){
            assert_eq!(text[i], decrypted[i])
        }

    }

    // must generate random key single time, key must be unknown: programmatic
    #[test]
    fn test_generate_random_key() {
        
        let test_size: usize = 100;
        let mut test_keys = Vec::with_capacity(test_size);
        for _x in 0..test_size {

            let test_key = generate_random_key();
            assert_eq!(test_key.len(), 16); // length check for fun.

            test_keys.push(test_key);
        }
        // validate all 100 keys generated are different, for fun.
        for i in 0..test_keys.len() {
            for j in 0..test_keys.len(){           
                if i != j { 
                    assert_ne!(&test_keys[i], &test_keys[j])
                }
            }
        }
    }

    //must programmatically decode (base64) CHALLTEXT -> before appending it.
    #[test]
    fn test_base64_decode() {
        
        // b64 endcoded by bash
        let enc = "TGlrZSB0aGUgYm95cyB3aGVuIHRoZXkncmUgb3V0IHRoZXJlIHdhbGtpbmcgdGhlIHN0cmVldHMuLi4K";
        let dec = decode(enc).unwrap();
        assert_eq!(
            str::from_utf8(&dec).unwrap(), 
            "Like the boys when they're out there walking the streets...\n")
    }

}