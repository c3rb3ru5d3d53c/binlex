use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LLVM_SYS_VERSION: &str = "221.0.1";

fn main() {
    let root = workspace_root();
    let vendor_dir = root.join("vendor/llvm-sys");
    let source_dir = ensure_registry_source_dir();

    if vendor_dir.exists() {
        fs::remove_dir_all(&vendor_dir).expect("remove existing vendor/llvm-sys");
    }
    copy_dir(&source_dir, &vendor_dir);

    fs::write(
        vendor_dir.join("build.rs"),
        include_str!("../templates/llvm-sys-build.rs"),
    )
    .expect("write patched llvm-sys build.rs");
    fs::write(
        vendor_dir.join("src/lib.rs"),
        include_str!("../templates/llvm-sys-lib.rs"),
    )
    .expect("write patched llvm-sys src/lib.rs");

    println!("patched llvm-sys written to {}", vendor_dir.display());
}

fn ensure_registry_source_dir() -> PathBuf {
    if let Some(path) = registry_source_dir() {
        return path;
    }

    run_checked(
        Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .arg("fetch")
            .arg("--locked"),
        "fetch workspace dependencies for xtask",
    );

    registry_source_dir().unwrap_or_else(|| {
        panic!(
            "llvm-sys-{LLVM_SYS_VERSION} was not found in the local cargo registry after cargo fetch"
        )
    })
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask under workspace root")
        .to_path_buf()
}

fn registry_source_dir() -> Option<PathBuf> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))?;
    let registry_src = cargo_home.join("registry/src");
    let entries = fs::read_dir(&registry_src).ok()?;
    for entry in entries.flatten() {
        let candidate = entry.path().join(format!("llvm-sys-{LLVM_SYS_VERSION}"));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create destination directory");
    for entry in fs::read_dir(src).expect("read source directory") {
        let entry = entry.expect("read directory entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type().expect("read file type");
        if file_type.is_dir() {
            copy_dir(&src_path, &dst_path);
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path).expect("copy file");
        }
    }
}

fn run_checked(command: &mut Command, context: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("{}: failed to spawn {:?}: {}", context, command, error));
    if !status.success() {
        panic!("{}: {:?} exited with status {}", context, command, status);
    }
}
