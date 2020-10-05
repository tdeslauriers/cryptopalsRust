use std::env;
use std::str;

// must count the byte length of the argument
fn is_less_than(a: usize, b: usize) -> bool {

    if a < b {
        return true;
    }

    return false;
}

// challenge input: "YELLOW SUBMARINE"

fn main() {
    // must take in a string argument <= 20 bytes
    let mut args: Vec<String> = env::args().collect();
    
    // must convert string to bytes
    let s = args.remove(1);
    let mut b = s.into_bytes();
    
    let block: usize = 20;
    
    // if less than 20, subtract from 20 and return diff.
    if is_less_than(b.len(), block) {
        let pad = block - b.len();
        let padx = pad as u8;
        
        // must PKCS#7 pad the string to 20 if necessary
        for _x in 0..pad {
            b.push(padx);
        }
        println!("Input + padding to 20 bytes: {:x?}", str::from_utf8(&b).unwrap());
        // Output: "Yellow Submarine\u{4}\u{4}\u{4}\u{4}"
        // Cant sort how to make the non-utf chars come out as \x0f"
        // but bytes inserted for padding to spec: 
        // if 4 bytes are missing, pads with byte value of 4

    }

}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_string_to_bytes(){
        //from docs
        let s = String::from("hello");
        let bytes = s.into_bytes();

        assert_eq!(&[104, 101, 108, 108, 111][..], &bytes[..]);
        println!("hello as bytes: {:#?}", bytes);
    }

    #[test]
    fn test_vec_len_boolean(){

        let check: usize = 4;
        let s = String::from("Tom");
        let b = s.into_bytes();

        println!("vector length: {}", b.len());
        assert!(is_less_than(b.len(), check));
    }

    #[test]
    fn sort_out_pkcs7() {
        
        let h = b'\x04';
        println!("What is this? {}", h);

        let x: i32 = 4;
        let y = x as u8;
        println!("Cast? {}", y);

        // the \x means hex
        let j: usize = 15;
        let k = j as u8;
        let m = b'\x0f';
        assert_eq!(k, m);
    }

    #[test]
    fn sort_out_pkcs7_more() {
        
        let s = String::from("Yellow Submarine");
        let mut b = s.into_bytes();
        let block: usize = 20;

        let pad = block - b.len();
        println!("test pad length: {}", pad);

        let bpad = pad.to_le_bytes();
        println!("little endian to bytes? - {:?}", bpad);
        
        for _x in 0..pad {
            b.push(bpad[0]);
        }

        println!("New Padded array: {:?}", b);
        println!("new padded array as string: {:x?}", str::from_utf8(&b).unwrap());
        
    }
}
