// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#[cfg(test)]
mod tests {

    use binlex::hashing::AHash;
    use binlex::hashing::DHash;
    use binlex::hashing::MinHash32;
    use binlex::hashing::PHash;
    use binlex::hashing::SHA256;
    use binlex::hashing::TLSH;
    use image::codecs::png::PngEncoder;
    use image::{ExtendedColorType, GrayImage, ImageEncoder};

    fn grayscale_png(width: u32, height: u32, pixels: Vec<u8>) -> Vec<u8> {
        let image = GrayImage::from_raw(width, height, pixels).unwrap();
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(image.as_raw(), width, height, ExtendedColorType::L8)
            .unwrap();
        bytes
    }

    #[test]
    fn test_models_hashing_sha256() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hash = SHA256::new(&data);
        let hexdigest = hash.hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(
            hexdigest.unwrap(),
            "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953",
            "hexdigest does not match the expected value"
        );
        let vector = hash.vector().unwrap();
        assert_eq!(
            vector.len(),
            32,
            "sha256 vector length should match digest bytes"
        );
        assert!(vector.iter().all(|value| (0.0..=1.0).contains(value)));
    }

    #[test]
    fn test_models_hashing_sha256_compare_helpers() {
        let lhs_data = vec![1u8, 2, 3, 4];
        let rhs_data = vec![1u8, 2, 3, 4];
        let other_data = vec![4u8, 3, 2, 1];

        let lhs = SHA256::new(&lhs_data);
        let rhs = SHA256::new(&rhs_data);
        let other = SHA256::new(&other_data);

        assert_eq!(lhs.compare(&rhs), Some(1.0));
        assert_eq!(lhs.compare(&other), Some(0.0));
        assert_eq!(lhs.compare_hexdigest(&rhs.hexdigest().unwrap()), Some(1.0));
        assert_eq!(
            lhs.compare_hexdigest(&other.hexdigest().unwrap()),
            Some(0.0)
        );
        assert_eq!(
            SHA256::compare_hexdigests(&lhs.hexdigest().unwrap(), &rhs.hexdigest().unwrap()),
            Some(1.0)
        );
        assert_eq!(
            SHA256::compare_hexdigests(&lhs.hexdigest().unwrap(), &other.hexdigest().unwrap()),
            Some(0.0)
        );
        assert!(SHA256::compare_hexdigests("zz", "00").is_none());
    }

    #[test]
    fn test_models_hashing_tlsh() {
        let data: Vec<u8> = vec![
            0x3A, 0x7F, 0x92, 0x5C, 0xE4, 0xA1, 0xD8, 0x47, 0x29, 0xB3, 0x1E, 0x8D, 0x4F, 0x6A,
            0xCD, 0x72, 0x90, 0x33, 0xB6, 0xF1, 0xD4, 0x5E, 0xAA, 0x64, 0x13, 0xFA, 0x38, 0x9C,
            0x41, 0xB8, 0xD0, 0xE7, 0x6F, 0x25, 0xA9, 0x54, 0x1B, 0xC2, 0x8E, 0xF5, 0x77, 0x3D,
            0xAC, 0x12, 0x8A, 0x9E, 0x6B, 0xC7, 0x5A, 0xEF,
        ];
        let hash = TLSH::new(&data, 50);
        let hexdigest = hash.hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(
            hexdigest.unwrap(),
            "T13390022E54110904084C76152B45D85A53A52164A647348D894A421D554C0266352468",
            "hexdigest does not match the expected value"
        );
        let vector = hash.vector().unwrap();
        assert_eq!(
            vector.len(),
            35,
            "tlsh vector length should match decoded digest bytes"
        );
        assert!(vector.iter().all(|value| (0.0..=1.0).contains(value)));
        assert!(TLSH::new(&data[..49], 50).vector().is_none());
    }

    #[test]
    fn test_models_hashing_minhash() {
        let data: Vec<u8> = vec![
            0x3A, 0x7F, 0x92, 0x5C, 0xE4, 0xA1, 0xD8, 0x47, 0x29, 0xB3, 0x1E, 0x8D, 0x4F, 0x6A,
            0xCD, 0x72, 0x90, 0x33, 0xB6, 0xF1, 0xD4, 0x5E, 0xAA, 0x64, 0x13, 0xFA, 0x38, 0x9C,
            0x41, 0xB8, 0xD0, 0xE7, 0x6F, 0x25, 0xA9, 0x54, 0x1B, 0xC2, 0x8E, 0xF5, 0x77, 0x3D,
            0xAC, 0x12, 0x8A, 0x9E, 0x6B, 0xC7, 0x5A, 0xEF,
        ];
        let hash = MinHash32::new(&data, 64, 4, 0);
        let hexdigest = hash.hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(
            hexdigest.unwrap(),
            "00510c10037f0c85108b1886039fba0907d95f6f012c5a570358233b016873a000ba1ef80b1cf59f0675d519066afadd021ae2420147ed0b084c726703cb11900eb906aa040ec25d01001a10011889ab040e3b94000fec940b2506870538268300e5e9b50a7740d70858815105789e8a03f7296d00c77bc600e3a1b800717a8e02da37480096176f00b442c30463506c032f0efe08c1512c02c057d10c612b8e046f8c5a05f06c0317ac542c06254c91023009c60bccf3510c1a81ef01b1cfd6021ddf2f04e63b4a03884e2b079acef81622d85901db282d05d417c103ba54c40b19a64c0b6720f102125783033628850147997d06ae204c0835ee0a06b3b80b",
            "hexdigest does not match the expected value"
        );
        let vector = hash.vector().unwrap();
        assert_eq!(
            vector.len(),
            64,
            "minhash vector length should match num_hashes"
        );
        assert!(vector.iter().all(|value| (0.0..=1.0).contains(value)));
    }

    #[test]
    fn test_models_hashing_ahash() {
        let pixels = (0..64)
            .map(|index| if index < 32 { 16u8 } else { 240u8 })
            .collect::<Vec<u8>>();
        let image = grayscale_png(8, 8, pixels);
        let hash = AHash::new(&image);
        let hexdigest = hash.hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(
            hexdigest.unwrap(),
            "00000000ffffffff",
            "hexdigest does not match the expected value"
        );
        let vector = hash.vector().unwrap();
        assert_eq!(vector.len(), 64, "ahash vector length should be 64 bits");
        assert!(vector.iter().all(|value| *value == 0.0 || *value == 1.0));
    }

    #[test]
    fn test_models_hashing_dhash() {
        let mut pixels = Vec::new();
        for _ in 0..8 {
            pixels.extend_from_slice(&[0, 32, 64, 96, 128, 160, 192, 224, 255]);
        }
        let image = grayscale_png(9, 8, pixels);
        let hash = DHash::new(&image);
        let hexdigest = hash.hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(
            hexdigest.unwrap(),
            "ffffffffffffffff",
            "hexdigest does not match the expected value"
        );
        let vector = hash.vector().unwrap();
        assert_eq!(vector.len(), 64, "dhash vector length should be 64 bits");
        assert!(vector.iter().all(|value| *value == 0.0 || *value == 1.0));
    }

    #[test]
    fn test_models_hashing_phash() {
        let mut pixels = Vec::new();
        for y in 0..32 {
            for x in 0..32 {
                pixels.push(((x * 8) ^ (y * 4)) as u8);
            }
        }
        let image = grayscale_png(32, 32, pixels);
        let hash = PHash::new(&image);
        let hexdigest = hash.hexdigest();
        assert!(hexdigest.is_some(), "hexdigest should not be none");
        assert_eq!(
            hexdigest.unwrap(),
            "bbaefffaffeffffb",
            "hexdigest does not match the expected value"
        );
        let vector = hash.vector().unwrap();
        assert_eq!(vector.len(), 64, "phash vector length should be 64 bits");
        assert!(vector.iter().all(|value| *value == 0.0 || *value == 1.0));
    }

    #[test]
    fn test_models_hashing_image_compare() {
        assert_eq!(
            AHash::compare_hexdigests("ffffffffffffffff", "ffffffffffffffff"),
            Some(1.0)
        );
        assert_eq!(
            DHash::compare_hexdigests("0000000000000000", "ffffffffffffffff"),
            Some(0.0)
        );
        assert_eq!(
            PHash::compare_hexdigests("0f0f0f0f0f0f0f0f", "0f0f0f0f0f0f0f0f"),
            Some(1.0)
        );
        assert!(AHash::compare_hexdigests("zz", "00").is_none());
    }

    #[test]
    fn test_models_hashing_compare_helpers() {
        let lhs_image = grayscale_png(8, 8, vec![240; 64]);
        let rhs_image = grayscale_png(8, 8, vec![240; 64]);
        let lhs = AHash::new(&lhs_image);
        let rhs = AHash::new(&rhs_image);

        assert_eq!(lhs.compare(&rhs), Some(1.0));
        assert_eq!(lhs.compare_hexdigest(&rhs.hexdigest().unwrap()), Some(1.0));

        let minhash_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let lhs_minhash = MinHash32::new(&minhash_data, 16, 4, 0);
        let rhs_minhash = MinHash32::new(&minhash_data, 16, 4, 0);
        let rhs_hex = rhs_minhash.hexdigest().unwrap();

        assert_eq!(lhs_minhash.compare(&rhs_minhash), Some(1.0));
        assert_eq!(lhs_minhash.compare_hexdigest(&rhs_hex), Some(1.0));
    }

    #[test]
    fn test_models_hashing_image_invalid_input() {
        let data = b"not-a-png";
        assert!(AHash::new(data).hexdigest().is_none());
        assert!(DHash::new(data).hexdigest().is_none());
        assert!(PHash::new(data).hexdigest().is_none());
        assert!(AHash::new(data).vector().is_none());
        assert!(DHash::new(data).vector().is_none());
        assert!(PHash::new(data).vector().is_none());
    }

    #[test]
    fn test_models_hashing_vectors_are_stable_for_equal_inputs() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let lhs_sha = SHA256::new(&data);
        let rhs_sha = SHA256::new(&data);
        assert_eq!(lhs_sha.vector(), rhs_sha.vector());

        let lhs_minhash = MinHash32::new(&data, 16, 4, 0);
        let rhs_minhash = MinHash32::new(&data, 16, 4, 0);
        assert_eq!(lhs_minhash.vector(), rhs_minhash.vector());
    }
}
