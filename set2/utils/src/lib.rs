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
}
