#[cfg(test)]
mod tests {
    use binlex::types::lz4string::LZ4String;
    #[test]
    fn test_types_lz4string() {
        let result = LZ4String::new("test");
        assert_eq!(result.to_string(), "test", "string failed to decompress correctly");
    }
}
