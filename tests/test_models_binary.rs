#[cfg(test)]
mod tests {
    use binlex::binary::Binary;

    #[test]
    fn test_models_binary_to_hex(){
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = Binary::to_hex(&data);
        assert_eq!(result, "deadbeef", "hex string does not match");
    }

    #[test]
    fn test_models_binary_hexdump() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = Binary::hexdump(&data, 0);
        assert_eq!(result, "00000000: de ad be ef                                     |....|\n", "hexdump string does not match");
    }
}
