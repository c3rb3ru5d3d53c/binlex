pub mod simplify;

pub(crate) use simplify::optimize_ast_function_with_timing;
pub use simplify::{optimize_ast_function, optimize_ast_module};
