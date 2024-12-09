use crate::controlflow::Gene;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct AllelePair {
    pub high: Gene,
    pub low: Gene,
}

#[allow(dead_code)]
impl AllelePair {
    pub fn to_string(&self) -> String {
        format!("{}{}", self.high.to_char(), self.low.to_char())
    }
}
