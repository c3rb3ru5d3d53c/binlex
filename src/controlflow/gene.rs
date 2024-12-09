#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum Gene {
    Wildcard,
    Value(u8),
}

#[allow(dead_code)]
impl Gene {
    pub fn to_char(self) -> String {
        match self {
            Gene::Wildcard => "?".to_string(),
            Gene::Value(v) => format!("{:x}", v),
        }
    }
}
