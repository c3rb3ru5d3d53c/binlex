#[cfg(test)]
mod tests {

    use binlex::hashing::SHA256;
    use binlex::hashing::TLSH;
    use binlex::hashing::MinHash32;

    #[test]
    fn test_models_hashing_sha256() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hexdigest = SHA256::new(&data).hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(hexdigest.unwrap(), "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953", "hexdigest does not match the expected value");
    }

    #[test]
    fn test_models_hashing_tlsh() {
        let data: Vec<u8> = vec![
            0x3A, 0x7F, 0x92, 0x5C, 0xE4, 0xA1, 0xD8, 0x47, 0x29, 0xB3,
            0x1E, 0x8D, 0x4F, 0x6A, 0xCD, 0x72, 0x90, 0x33, 0xB6, 0xF1,
            0xD4, 0x5E, 0xAA, 0x64, 0x13, 0xFA, 0x38, 0x9C, 0x41, 0xB8,
            0xD0, 0xE7, 0x6F, 0x25, 0xA9, 0x54, 0x1B, 0xC2, 0x8E, 0xF5,
            0x77, 0x3D, 0xAC, 0x12, 0x8A, 0x9E, 0x6B, 0xC7, 0x5A, 0xEF];
        let hexdigest = TLSH::new(&data, 50).hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(hexdigest.unwrap(), "T13390022E54110904084C76152B45D85A53A52164A647348D894A421D554C0266352468", "hexdigest does not match the expected value");
    }

    #[test]
    fn test_models_hashing_minhash() {
        let data: Vec<u8> = vec![
            0x3A, 0x7F, 0x92, 0x5C, 0xE4, 0xA1, 0xD8, 0x47, 0x29, 0xB3,
            0x1E, 0x8D, 0x4F, 0x6A, 0xCD, 0x72, 0x90, 0x33, 0xB6, 0xF1,
            0xD4, 0x5E, 0xAA, 0x64, 0x13, 0xFA, 0x38, 0x9C, 0x41, 0xB8,
            0xD0, 0xE7, 0x6F, 0x25, 0xA9, 0x54, 0x1B, 0xC2, 0x8E, 0xF5,
            0x77, 0x3D, 0xAC, 0x12, 0x8A, 0x9E, 0x6B, 0xC7, 0x5A, 0xEF];
        let hexdigest = MinHash32::new(&data, 64, 4, 0).hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(hexdigest.unwrap(), "00510c10037f0c85108b1886039fba0907d95f6f012c5a570358233b016873a000ba1ef80b1cf59f0675d519066afadd021ae2420147ed0b084c726703cb11900eb906aa040ec25d01001a10011889ab040e3b94000fec940b2506870538268300e5e9b50a7740d70858815105789e8a03f7296d00c77bc600e3a1b800717a8e02da37480096176f00b442c30463506c032f0efe08c1512c02c057d10c612b8e046f8c5a05f06c0317ac542c06254c91023009c60bccf3510c1a81ef01b1cfd6021ddf2f04e63b4a03884e2b079acef81622d85901db282d05d417c103ba54c40b19a64c0b6720f102125783033628850147997d06ae204c0835ee0a06b3b80b", "hexdigest does not match the expected value");
    }

}
