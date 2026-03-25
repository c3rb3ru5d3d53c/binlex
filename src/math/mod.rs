pub mod entropy;
pub mod similarity;
pub mod stats;

pub use entropy::shannon;
pub use similarity::chebyshev;
pub use similarity::cosine;
pub use similarity::dice;
pub use similarity::dot;
pub use similarity::euclidean;
pub use similarity::hamming;
pub use similarity::jaccard_set;
pub use similarity::jaccard_signature;
pub use similarity::manhattan;
pub use similarity::overlap_coefficient;
pub use similarity::pearson;
pub use stats::*;
