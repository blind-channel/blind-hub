#[cfg(test)]
mod tests{
    use aes::cipher::{KeyInit, BlockEncrypt, generic_array::{GenericArray, typenum::U16}};
    use bitcoin::hashes::hex::{FromHex, ToHex};

    #[test]
    fn test_aes256_encrypt(){
        let key: [u8;32] = Vec::<u8>::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ).unwrap().try_into().unwrap();
        let msg: [u8;16] = Vec::<u8>::from_hex(
            "00112233445566778899aabbccddeeff"
        ).unwrap().try_into().unwrap();
        // let key = [0u8;32];
        // let msg = [0u8;16];
        let aes = aes::Aes256::new(&key.into());
        let mut out = GenericArray::<u8,U16>::default();
        aes.encrypt_block_b2b(&msg.into(), &mut out);
        dbg!(key.as_slice().to_hex());
        dbg!(msg.as_slice().to_hex());
        dbg!(out.as_slice().to_hex());
    }

    #[test]
    fn test_aes128_encrypt(){
        let key: [u8;16] = Vec::<u8>::from_hex(
            "f00102030405060708090a0b0c0d0e0f"
        ).unwrap().try_into().unwrap();
        let msg: [u8;16] = Vec::<u8>::from_hex(
            "f0112233445566778899aabbccddeeff"
        ).unwrap().try_into().unwrap();
        // let key = [0u8;16];
        // let msg = [0u8;16];
        let aes = aes::Aes128::new(&key.into());
        let mut out = GenericArray::<u8,U16>::default();
        aes.encrypt_block_b2b(&msg.into(), &mut out);
        dbg!(key.as_slice().to_hex());
        dbg!(msg.as_slice().to_hex());
        dbg!(out.as_slice().to_hex());
    }
}