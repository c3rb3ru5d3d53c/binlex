pub mod branches;
pub mod casts;
pub mod constants;
pub mod identities;
pub mod intrinsics;
pub mod noops;
pub mod simplify;

pub use branches::optimize_branches;
pub use casts::optimize_casts;
pub use constants::optimize_constants;
pub use identities::optimize_identities;
pub use intrinsics::optimize_intrinsics;
pub use noops::optimize_noops;
pub use simplify::optimize;
