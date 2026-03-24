//! Public indexing types and orchestration.

pub mod collection;
pub mod local;

pub use collection::Collection;
pub use local::LocalIndex;
pub use local::SearchResult;
pub type Entity = Collection;
