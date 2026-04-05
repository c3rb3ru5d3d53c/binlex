//! Public indexing types and orchestration.

pub mod collection;
pub mod local;

pub use collection::Collection;
pub use local::CollectionCommentRecord;
pub use local::CollectionCommentSearchPage;
pub use local::CollectionTagRecord;
pub use local::CollectionTagSearchPage;
pub use local::CommentRecord;
pub use local::CommentSearchPage;
pub use local::CompareResult;
pub use local::LocalIndex;
pub use local::QueryResult;
pub use local::SampleStatusRecord;
pub use local::SearchResult;
pub use local::TagRecord;
pub use local::TagSearchPage;
pub type Entity = Collection;
