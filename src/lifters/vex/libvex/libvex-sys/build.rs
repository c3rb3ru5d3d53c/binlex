use std::env::{self, VarError};
use std::error::Error;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use fs_extra::dir::{copy, CopyOptions};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const VALGRIND_MACOS_REPO: &str = "https://github.com/LouisBrunner/valgrind-macos.git";
const VALGRIND_REPO: &str = "https://sourceware.org/git/valgrind.git";
const VALGRIND_REV: &str = "0062f2b519ea48b82164ae423fac58a59ee00f1a";
const VEX_ENV_KEYS: [&str; 3] = ["VEX_SRC", "VEX_HEADERS", "VEX_LIBS"];

fn vex_headers() -> Result<Vec<String>> {
    match env::var("VEX_HEADERS") {
        Ok(paths) => Ok(paths.split(':').map(String::from).collect()),
        Err(VarError::NotPresent) => {
            let mut vex = find_vex()?;
            let mut res = Vec::with_capacity(2);
            res.push(vex.to_string_lossy().into_owned());
            vex.pop();
            res.push(vex.to_string_lossy().into_owned());
            Ok(res)
        }
        Err(err) => Err(err.into()),
    }
}

fn run_checked(program: &str, args: &[&str], cwd: &Path) -> Result<()> {
    let status = Command::new(program).args(args).current_dir(cwd).status()?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "`{}` failed in {} with status {}",
        format_command(program, args),
        cwd.display(),
        status
    )
    .into())
}

fn run_checked_with_env(
    program: &str,
    args: &[&str],
    cwd: &Path,
    envs: &[(&str, &str)],
) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args).current_dir(cwd);
    for (key, value) in envs {
        command.env(key, value);
    }
    let status = command.status()?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "`{}` failed in {} with status {}",
        format_command(program, args),
        cwd.display(),
        status
    )
    .into())
}

fn format_command(program: &str, args: &[&str]) -> String {
    let mut rendered = String::from(program);
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    rendered
}

fn host_arch() -> Result<String> {
    Ok(env::var("HOST")?
        .split('-')
        .next()
        .ok_or("missing host arch")?
        .to_string())
}

fn target_triple() -> Result<String> {
    Ok(env::var("TARGET")?)
}

fn target_os() -> Result<String> {
    let triple = target_triple()?;
    let mut parts = triple.split('-');
    let _arch = parts.next();
    let _vendor = parts.next();
    let os = parts.next().ok_or("missing target os")?;
    Ok(match os {
        "darwin" => "macos".to_string(),
        other => other.to_string(),
    })
}

fn target_arch_and_platform() -> Result<(String, String)> {
    let triple = target_triple()?;
    let mut parts = triple.split('-');
    let arch = match parts.next().ok_or("missing target arch")? {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
    .to_string();
    let _vendor = parts.next();
    let platform = parts.next().ok_or("missing target platform")?.to_string();
    Ok((arch, platform))
}

fn cpu_count() -> String {
    std::thread::available_parallelism()
        .map(|count| count.get().to_string())
        .unwrap_or_else(|_| "1".to_string())
}

fn patch_is_already_applied(valgrind_dir: &Path, patch_path: &Path) -> Result<bool> {
    let status = Command::new("patch")
        .args(["--dry-run", "-R", "-p1", "-i"])
        .arg(patch_path)
        .current_dir(valgrind_dir)
        .status()?;
    Ok(status.success())
}

fn patch_can_be_applied(valgrind_dir: &Path, patch_path: &Path) -> Result<bool> {
    let status = Command::new("patch")
        .args(["--dry-run", "-p1", "-i"])
        .arg(patch_path)
        .current_dir(valgrind_dir)
        .status()?;
    Ok(status.success())
}

fn apply_patch_file(valgrind_dir: &Path, patch_path: &Path) -> Result<()> {
    if patch_is_already_applied(valgrind_dir, patch_path)? {
        return Ok(());
    }

    if !patch_can_be_applied(valgrind_dir, patch_path)? {
        return Err(format!("patch {} cannot be applied cleanly", patch_path.display()).into());
    }

    let status = Command::new("patch")
        .args(["-p1", "-i"])
        .arg(patch_path)
        .current_dir(valgrind_dir)
        .status()?;
    if status.success() {
        return Ok(());
    }

    Err(format!(
        "failed to apply patch {} with status {}",
        patch_path.display(),
        status
    )
    .into())
}

fn apply_patches(valgrind_dir: &Path, patch_dir: &Path) -> Result<()> {
    if !patch_dir.exists() {
        return Ok(());
    }

    println!("cargo:rerun-if-changed={}", patch_dir.display());
    let mut entries = patch_dir
        .read_dir()?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let patch_path = entry.path();
        let extension = patch_path.extension();
        if extension != Some(OsStr::new("patch")) && extension != Some(OsStr::new("diff")) {
            continue;
        }

        apply_patch_file(valgrind_dir, &patch_path)?;
    }
    Ok(())
}

fn default_patch_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("patches"))
}

fn apply_configured_patches(valgrind_dir: &Path) -> Result<()> {
    apply_patches(valgrind_dir, &default_patch_dir()?)?;
    match env::var("VEX_PATCHES") {
        Ok(path) => apply_patches(valgrind_dir, Path::new(&path))?,
        Err(VarError::NotUnicode(path)) => apply_patches(valgrind_dir, Path::new(&path))?,
        Err(VarError::NotPresent) => {}
    }
    Ok(())
}

fn copy_valgrind(out_dir: &Path, valgrind_dir_name: &str) -> Result<()> {
    let mut options = CopyOptions::default();
    options.copy_inside = true;
    let source_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join(valgrind_dir_name);
    copy(&source_dir, out_dir, &options)?;
    println!("cargo:rerun-if-changed={}", source_dir.display());
    apply_configured_patches(&out_dir.join(valgrind_dir_name))?;
    Ok(())
}

fn clone_repo(repo: &str, dest: &Path, shallow: bool) -> Result<()> {
    let parent = dest.parent().ok_or("clone destination missing parent")?;
    let dest_str = dest.to_string_lossy().into_owned();
    if shallow {
        run_checked(
            "git",
            &["clone", "--depth", "1", repo, dest_str.as_str()],
            parent,
        )
    } else {
        run_checked("git", &["clone", repo, dest_str.as_str()], parent)
    }
}

fn checkout_repo_revision(dest: &Path, revision: &str) -> Result<()> {
    run_checked("git", &["checkout", revision], dest)
}

fn bootstrap_macos_vex() -> Result<PathBuf> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let valgrind_dir = out_dir.join("valgrind-macos");
    let vex_dir = valgrind_dir.join("VEX");
    let host_arch = host_arch()?;

    println!("cargo:rerun-if-env-changed=VEX_SRC");
    println!("cargo:rerun-if-env-changed=VEX_HEADERS");
    println!("cargo:rerun-if-env-changed=VEX_LIBS");

    if !valgrind_dir.exists() {
        clone_repo(VALGRIND_MACOS_REPO, &valgrind_dir, true)?;
    }

    println!("cargo:rerun-if-changed={}", valgrind_dir.display());
    apply_configured_patches(&valgrind_dir)?;

    if !valgrind_dir.join("configure").exists() {
        run_checked("./autogen.sh", &[], &valgrind_dir)?;
    }

    if !valgrind_dir.join("Makefile").exists() {
        let mut args = Vec::new();
        let mut envs = Vec::new();
        if matches!(host_arch.as_str(), "aarch64" | "arm64") {
            args.push("--enable-only64bit");
            envs.push((
                "I_ACKNOWLEDGE_THIS_MIGHT_CRASH_OR_DAMAGE_MY_COMPUTER",
                "yes",
            ));
        }
        run_checked_with_env("./configure", &args, &valgrind_dir, &envs)?;
    }

    if !vex_has_libs(&vex_dir) {
        let mut envs = Vec::new();
        if matches!(host_arch.as_str(), "aarch64" | "arm64") {
            envs.push((
                "I_ACKNOWLEDGE_THIS_MIGHT_CRASH_OR_DAMAGE_MY_COMPUTER",
                "yes",
            ));
        }
        let jobs = cpu_count();
        let make_args = ["-j", jobs.as_str()];
        run_checked_with_env("make", &make_args, &vex_dir, &envs)?;
    }

    let vex_src = valgrind_dir.to_string_lossy().into_owned();
    let vex_headers = format!("{}:{}", vex_dir.display(), valgrind_dir.display());
    let vex_libs = vex_dir.to_string_lossy().into_owned();
    for (key, value) in [
        ("VEX_SRC", vex_src),
        ("VEX_HEADERS", vex_headers),
        ("VEX_LIBS", vex_libs),
    ] {
        env::set_var(key, &value);
        println!("cargo:rustc-env={key}={value}");
    }

    Ok(vex_dir)
}

fn fetch_valgrind_source(out_dir: &Path) -> Result<PathBuf> {
    let valgrind_dir = out_dir.join("valgrind");
    if !valgrind_dir.exists() {
        clone_repo(VALGRIND_REPO, &valgrind_dir, false)?;
        checkout_repo_revision(&valgrind_dir, VALGRIND_REV)?;
    } else {
        let head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&valgrind_dir)
            .output()?;
        if !head.status.success() || String::from_utf8_lossy(&head.stdout).trim() != VALGRIND_REV {
            run_checked("git", &["fetch", "origin", VALGRIND_REV], &valgrind_dir)?;
            checkout_repo_revision(&valgrind_dir, VALGRIND_REV)?;
        }
    }
    println!("cargo:rerun-if-changed={}", valgrind_dir.display());
    apply_configured_patches(&valgrind_dir)?;
    Ok(valgrind_dir)
}

fn vex_has_libs(vex_dir: &Path) -> bool {
    if let Ok(entries) = vex_dir.read_dir() {
        return entries.filter_map(|entry| entry.ok()).any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("libvex-") && name.ends_with(".a")
        });
    }
    false
}

fn find_vex() -> Result<PathBuf> {
    let is_macos = target_os()? == "macos";
    match env::var("VEX_SRC") {
        Ok(path) => {
            println!("cargo:rerun-if-changed={path}");
            Ok(PathBuf::from(path))
        }
        Err(VarError::NotUnicode(path)) => Ok(PathBuf::from(path)),
        Err(VarError::NotPresent) if is_macos => {
            let vex_dir = bootstrap_macos_vex()?;
            Ok(vex_dir
                .parent()
                .ok_or("macOS VEX directory missing parent")?
                .to_path_buf())
        }
        Err(VarError::NotPresent) => {
            let out_dir = PathBuf::from(env::var("OUT_DIR")?);
            let valgrind_dir_name = "valgrind";
            let source_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join(valgrind_dir_name);
            let valgrind_dir = if source_dir.join("autogen.sh").exists() {
                let valgrind_dir = out_dir.join(valgrind_dir_name);
                if !valgrind_dir.exists() {
                    copy_valgrind(&out_dir, valgrind_dir_name)?;
                }
                valgrind_dir
            } else {
                fetch_valgrind_source(&out_dir)?
            };
            if !valgrind_dir.join("configure").exists() {
                run_checked("./autogen.sh", &[], &valgrind_dir)?;
            }
            if !valgrind_dir.join("VEX").join("Makefile").exists() {
                let mut args = Vec::new();
                if cfg!(feature = "pic") {
                    args.push("CFLAGS=-fPIC");
                }
                run_checked("./configure", &args, &valgrind_dir)?;
            }
            Ok(valgrind_dir.join("VEX"))
        }
    }
}

fn compile_vex() -> Result<PathBuf> {
    let src_dir = find_vex()?;
    let jobs = env::var("CARGO_MAKEFLAGS").unwrap_or_default();
    let mut command = Command::new("make");
    command.current_dir(&src_dir);
    if !jobs.is_empty() {
        command.env("MAKEFLAGS", jobs);
    } else {
        command.arg("-j").arg(cpu_count());
    }
    let status = command.status()?;
    if !status.success() {
        return Err(format!(
            "`make` failed in {} with status {}",
            src_dir.display(),
            status
        )
        .into());
    }

    Ok(src_dir)
}

fn ensure_lib() -> Result<PathBuf> {
    let is_macos = target_os()? == "macos";
    match env::var("VEX_LIBS") {
        Ok(path) => Ok(PathBuf::from(path)),
        Err(VarError::NotUnicode(path)) => Ok(PathBuf::from(path)),
        Err(VarError::NotPresent) if is_macos => bootstrap_macos_vex(),
        Err(VarError::NotPresent) => compile_vex(),
    }
}

fn main() -> Result<()> {
    for key in VEX_ENV_KEYS {
        println!("cargo:rerun-if-env-changed={key}");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let (arch, platform) = target_arch_and_platform()?;

    let vex_dir = ensure_lib()?;
    println!("cargo:rustc-link-search=native={}", vex_dir.display());
    let multiarch_lib = format!("vexmultiarch-{}-{}", arch, platform);
    let singlearch_lib = format!("vex-{}-{}", arch, platform);
    if vex_dir.join(format!("lib{multiarch_lib}.a")).exists() {
        println!("cargo:rustc-link-lib=static={multiarch_lib}");
    }
    println!("cargo:rustc-link-lib=static={singlearch_lib}");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .blocklist_type("_IRStmt__bindgen_ty_1__bindgen_ty_1")
        .rustified_enum(".*")
        .clang_args(vex_headers()?.into_iter().map(|dir| format!("-I{dir}")))
        .generate()
        .map_err(|_| "Unable to generate bindings")?;
    bindings.write_to_file(out_dir.join("bindings.rs"))?;

    Ok(())
}
