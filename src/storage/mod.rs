//! Public storage backends and persistence-oriented types.

pub mod localstore;
pub mod minio;
pub mod object_store;

pub use localstore::LocalStore;
pub use minio::MinIO;
pub use object_store::ObjectStore;
