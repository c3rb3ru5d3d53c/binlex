#[cfg(not(target_os = "windows"))]
pub mod vex;

#[cfg(not(target_os = "windows"))]
pub use vex::Vex;
