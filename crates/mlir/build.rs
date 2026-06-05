use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

const LLVM_TAG: &str = "llvmorg-22.1.3";
const LLVM_GIT_URL: &str = "https://github.com/llvm/llvm-project.git";
const PREFIX_ENV: &str = "BINLEX_MLIR_PREFIX";
const LLVM_PREFIX_ENV: &str = "LLVM_SYS_221_PREFIX";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BINLEX_LLVM_PARALLEL_JOBS");
    println!("cargo:rerun-if-env-changed=BINLEX_LLVM_PARALLEL_COMPILE_JOBS");
    println!("cargo:rerun-if-env-changed=BINLEX_LLVM_PARALLEL_LINK_JOBS");
    println!("cargo:rerun-if-env-changed=CMAKE_BUILD_PARALLEL_LEVEL");
    println!("cargo:rerun-if-env-changed=NUM_JOBS");

    if target_env_is("gnu") && !target_os_is("macos") {
        println!("cargo:rustc-link-arg=-Wl,--exclude-libs,ALL");
        println!("cargo:rustc-link-arg=-Wl,--start-group");
    }

    let install = ensure_mlir_install();
    emit_linking(&install);

    if target_env_is("gnu") && !target_os_is("macos") {
        println!("cargo:rustc-link-arg=-Wl,--end-group");
    }
}

#[derive(Clone, Debug)]
struct LlvmInstall {
    llvm_config: PathBuf,
    libdir: String,
}

fn ensure_mlir_install() -> LlvmInstall {
    if let Some(llvm_config_path) = env_llvm_config_path() {
        if mlir_install_ready(
            llvm_config_path
                .parent()
                .and_then(Path::parent)
                .unwrap_or(&llvm_config_path),
        ) {
            return load_llvm_install(llvm_config_path);
        }
    }

    let install_prefix = shared_mlir_install_prefix();
    let llvm_config_path = expected_llvm_config_path(&install_prefix);
    if !mlir_install_ready(&install_prefix) {
        bootstrap_static_mlir(&install_prefix);
    }
    if !mlir_install_ready(&install_prefix) {
        panic!(
            "static mlir bootstrap completed without installing MLIR headers and libraries into {}",
            install_prefix.display()
        );
    }

    load_llvm_install(llvm_config_path)
}

fn load_llvm_install(llvm_config_path: PathBuf) -> LlvmInstall {
    LlvmInstall {
        libdir: llvm_config(&llvm_config_path, &["--libdir"]),
        llvm_config: llvm_config_path,
    }
}

fn emit_linking(install: &LlvmInstall) {
    let libdir = install.libdir.trim();
    println!("cargo:rustc-link-search=native={libdir}");
    emit_mlir_static_libs(Path::new(libdir));
    emit_llvm_static_libs(install);
    emit_system_libs(install);
    if let Some(cpp_stdlib) = cpp_stdlib() {
        println!("cargo:rustc-link-lib=dylib={cpp_stdlib}");
    }
}

fn emit_mlir_static_libs(libdir: &Path) {
    let mut capi_libs = Vec::new();
    let mut core_libs = Vec::new();

    let entries = std::fs::read_dir(libdir).unwrap_or_else(|error| {
        panic!("failed to read MLIR libdir {}: {}", libdir.display(), error)
    });

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|item| item.to_str()) else {
            continue;
        };
        if !is_static_mlir_library_name(name) {
            continue;
        }
        let normalized = normalize_library_name(name);
        if normalized.starts_with("MLIRCAPI") {
            capi_libs.push(normalized);
        } else {
            core_libs.push(normalized);
        }
    }

    capi_libs.sort();
    capi_libs.dedup();
    core_libs.sort();
    core_libs.dedup();

    if capi_libs.is_empty() {
        panic!(
            "no static MLIR C API archives were found in {}",
            libdir.display()
        );
    }

    for lib in capi_libs.into_iter().chain(core_libs) {
        println!("cargo:rustc-link-lib=static={lib}");
    }
}

fn emit_llvm_static_libs(install: &LlvmInstall) {
    for lib in shell_words(&llvm_config(
        &install.llvm_config,
        &["--libnames", "--link-static", "all"],
    )) {
        if is_static_library_name(&lib) {
            println!(
                "cargo:rustc-link-lib=static={}",
                normalize_library_name(&lib)
            );
        }
    }
}

fn emit_system_libs(install: &LlvmInstall) {
    for lib in shell_words(&llvm_config(
        &install.llvm_config,
        &["--system-libs", "--link-static"],
    )) {
        emit_system_lib(install, &lib);
    }
}

fn bootstrap_static_mlir(install_prefix: &Path) {
    if mlir_install_ready(install_prefix) {
        return;
    }

    let bootstrap_root = target_dir().join("mlir-bootstrap");
    let lock_dir = bootstrap_root.join("bootstrap.lock");
    std::fs::create_dir_all(&bootstrap_root).expect("create mlir bootstrap root");

    loop {
        match std::fs::create_dir(&lock_dir) {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if mlir_install_ready(install_prefix) {
                    return;
                }
                if stale_lock_dir(&lock_dir) {
                    let _ = std::fs::remove_dir_all(&lock_dir);
                    continue;
                }
                thread::sleep(Duration::from_secs(1));
            }
            Err(error) => panic!("failed to acquire mlir bootstrap lock: {}", error),
        }
    }

    let result = (|| {
        if mlir_install_ready(install_prefix) {
            return;
        }

        let source_root = bootstrap_root.join("src");
        let repo_root = source_root.join("llvm-project");
        let llvm_source = repo_root.join("llvm");
        if !llvm_source.exists() {
            std::fs::create_dir_all(&source_root).expect("create mlir source root");
            run_checked(
                Command::new("git")
                    .arg("clone")
                    .arg("--depth=1")
                    .arg("--branch")
                    .arg(LLVM_TAG)
                    .arg("--single-branch")
                    .arg(LLVM_GIT_URL)
                    .arg(&repo_root),
                "clone llvm-project for mlir bootstrap",
            );
        }

        let generator = cmake_generator();
        let build_dir = bootstrap_root.join(format!(
            "build-{}",
            generator.to_ascii_lowercase().replace(' ', "-")
        ));
        std::fs::create_dir_all(&build_dir).expect("create mlir build dir");
        std::fs::create_dir_all(install_prefix).expect("create mlir install dir");

        let compile_jobs = llvm_parallel_compile_jobs();
        let link_jobs = llvm_parallel_link_jobs();

        let mut configure = Command::new("cmake");
        configure
            .arg("-S")
            .arg(&llvm_source)
            .arg("-B")
            .arg(&build_dir)
            .arg("-G")
            .arg(generator)
            .arg("-DCMAKE_BUILD_TYPE=Release")
            .arg(format!(
                "-DCMAKE_INSTALL_PREFIX={}",
                install_prefix.display()
            ))
            .arg("-DBUILD_SHARED_LIBS=OFF")
            .arg("-DLLVM_BUILD_LLVM_DYLIB=OFF")
            .arg("-DLLVM_LINK_LLVM_DYLIB=OFF")
            .arg("-DLLVM_TARGETS_TO_BUILD=X86;AArch64")
            .arg("-DLLVM_INCLUDE_TESTS=OFF")
            .arg("-DLLVM_INCLUDE_BENCHMARKS=OFF")
            .arg("-DLLVM_INCLUDE_EXAMPLES=OFF")
            .arg("-DLLVM_INCLUDE_DOCS=OFF")
            .arg("-DLLVM_ENABLE_ASSERTIONS=OFF")
            .arg("-DLLVM_ENABLE_LIBXML2=OFF")
            .arg("-DLLVM_ENABLE_TERMINFO=OFF")
            .arg("-DLLVM_ENABLE_LIBEDIT=OFF")
            .arg("-DLLVM_ENABLE_ZSTD=OFF")
            .arg("-DLLVM_ENABLE_ZLIB=OFF")
            .arg("-DLLVM_ENABLE_PROJECTS=mlir")
            .arg("-DMLIR_BUILD_MLIR_C_DYLIB=OFF")
            .arg("-DMLIR_INCLUDE_TESTS=OFF")
            .arg("-DMLIR_INCLUDE_INTEGRATION_TESTS=OFF")
            .arg("-DMLIR_INCLUDE_DOCS=OFF")
            .arg("-DMLIR_INCLUDE_EXAMPLES=OFF")
            .arg("-DMLIR_ENABLE_BINDINGS_PYTHON=OFF")
            .arg(format!("-DLLVM_PARALLEL_COMPILE_JOBS={compile_jobs}"))
            .arg(format!("-DLLVM_PARALLEL_LINK_JOBS={link_jobs}"))
            .arg("-DCMAKE_SKIP_INSTALL_RPATH=ON")
            .arg("-DCMAKE_SKIP_RPATH=ON");
        configure_bootstrap_compilers(&mut configure);
        run_checked(&mut configure, "configure mlir bootstrap");
        let mut build = cmake_build_command(&build_dir);
        run_checked(&mut build, "build mlir bootstrap");
    })();

    let _ = std::fs::remove_dir(&lock_dir);
    result
}

fn cmake_generator() -> &'static str {
    if command_exists("ninja") {
        "Ninja"
    } else if target_os_is("windows") {
        "Visual Studio 17 2022"
    } else {
        "Unix Makefiles"
    }
}

fn target_dir() -> PathBuf {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    out_dir
        .ancestors()
        .find(|path| path.file_name().and_then(|item| item.to_str()) == Some("target"))
        .expect("derive target dir from OUT_DIR")
        .to_path_buf()
}

fn shared_mlir_install_prefix() -> PathBuf {
    target_dir().join("mlir-bootstrap").join("install")
}

fn expected_llvm_config_path(install_prefix: &Path) -> PathBuf {
    install_prefix.join("bin").join(if target_os_is("windows") {
        "llvm-config.exe"
    } else {
        "llvm-config"
    })
}

fn mlir_install_ready(install_prefix: &Path) -> bool {
    expected_llvm_config_path(install_prefix).exists()
        && install_prefix
            .join("include")
            .join("mlir-c")
            .join("IR.h")
            .exists()
        && install_prefix
            .join("lib")
            .join(static_library_filename("MLIRCAPIIR"))
            .exists()
        && install_prefix
            .join("lib")
            .join(static_library_filename("MLIRCAPIRegisterEverything"))
            .exists()
}

fn static_library_filename(name: &str) -> String {
    if target_env_is("msvc") {
        format!("{name}.lib")
    } else {
        format!("lib{name}.a")
    }
}

fn env_llvm_config_path() -> Option<PathBuf> {
    if let Some(prefix) = std::env::var_os(PREFIX_ENV) {
        return Some(expected_llvm_config_path(&PathBuf::from(prefix)));
    }
    let prefix = std::env::var_os(LLVM_PREFIX_ENV)?;
    Some(expected_llvm_config_path(&PathBuf::from(prefix)))
}

fn llvm_config(llvm_config_path: &Path, args: &[&str]) -> String {
    llvm_config_try(llvm_config_path, args)
        .unwrap_or_else(|error| panic!("llvm-config invocation failed: {}", error))
}

fn llvm_config_try(llvm_config_path: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(llvm_config_path)
        .args(args)
        .output()
        .map_err(|error| format!("{}: {}", llvm_config_path.display(), error))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(stderr.trim().to_string());
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn shell_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_library_name(path_or_flag: &str) -> String {
    let path = PathBuf::from(path_or_flag);
    let name = path
        .file_name()
        .and_then(|item| item.to_str())
        .unwrap_or(path_or_flag);
    let name = name.strip_prefix("lib").unwrap_or(name);
    let name = name.strip_suffix(".a").unwrap_or(name);
    let name = name.strip_suffix(".lib").unwrap_or(name);
    name.to_string()
}

fn emit_system_lib(install: &LlvmInstall, flag: &str) {
    if let Some(name) = flag.strip_prefix("-l") {
        emit_external_system_search_paths(install, name);
        println!("cargo:rustc-link-lib={name}");
    } else if is_static_library_name(flag) {
        println!(
            "cargo:rustc-link-lib=static={}",
            normalize_library_name(flag)
        );
    } else if flag.ends_with(".lib") {
        println!("cargo:rustc-link-lib={}", normalize_library_name(flag));
    } else if let Some(path) = flag.strip_prefix("-L") {
        println!("cargo:rustc-link-search=native={path}");
    }
}

fn emit_external_system_search_paths(install: &LlvmInstall, name: &str) {
    let mut search_paths = Vec::new();
    let llvm_libdir = PathBuf::from(install.libdir.trim());
    if llvm_libdir.exists() {
        search_paths.push(llvm_libdir.clone());
    }

    if target_os_is("macos") {
        if let Some(llvm_prefix) = llvm_libdir.parent() {
            let sibling_lib = llvm_prefix
                .parent()
                .map(|prefix_root| prefix_root.join(name).join("lib"));
            if let Some(sibling_lib) = sibling_lib.filter(|path| path.exists()) {
                search_paths.push(sibling_lib);
            }

            let homebrew_lib = llvm_prefix
                .parent()
                .and_then(|prefix_root| prefix_root.parent())
                .map(|brew_root| brew_root.join("lib"));
            if let Some(homebrew_lib) = homebrew_lib.filter(|path| path.exists()) {
                search_paths.push(homebrew_lib);
            }
        }
    }

    search_paths.sort();
    search_paths.dedup();
    for path in search_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
}

fn is_static_mlir_library_name(value: &str) -> bool {
    if target_env_is("msvc") {
        value.starts_with("MLIR") && value.ends_with(".lib")
    } else {
        value.starts_with("libMLIR") && value.ends_with(".a")
    }
}

fn is_static_library_name(value: &str) -> bool {
    value.ends_with(".a") || (target_env_is("msvc") && value.ends_with(".lib"))
}

fn cpp_stdlib() -> Option<&'static str> {
    if target_env_is("msvc") {
        None
    } else if target_os_is("macos") || target_os_is("freebsd") || target_os_is("openbsd") {
        Some("c++")
    } else {
        Some("stdc++")
    }
}

fn target_os_is(name: &str) -> bool {
    std::env::var_os("CARGO_CFG_TARGET_OS").is_some_and(|value| value == name)
}

fn target_env_is(name: &str) -> bool {
    std::env::var_os("CARGO_CFG_TARGET_ENV").is_some_and(|value| value == name)
}

fn target_feature_is_enabled(name: &str) -> bool {
    std::env::var("CARGO_CFG_TARGET_FEATURE")
        .ok()
        .is_some_and(|features| features.split(',').any(|feature| feature == name))
}

fn configure_bootstrap_compilers(command: &mut Command) -> &mut Command {
    if target_env_is("msvc") {
        command.arg("-DCMAKE_POLICY_DEFAULT_CMP0091=NEW");
        command.arg(format!(
            "-DCMAKE_MSVC_RUNTIME_LIBRARY={}",
            if target_feature_is_enabled("crt-static") {
                "MultiThreaded"
            } else {
                "MultiThreadedDLL"
            }
        ));
        return command;
    }

    command.arg(format!(
        "-DCMAKE_C_COMPILER={}",
        detect_compiler("CC", &["cc", "gcc", "clang"]).display()
    ));
    command.arg(format!(
        "-DCMAKE_CXX_COMPILER={}",
        detect_compiler("CXX", &["c++", "g++", "clang++"]).display()
    ));
    command
}

fn cmake_build_command(build_dir: &Path) -> Command {
    let mut command = Command::new("cmake");
    command
        .arg("--build")
        .arg(build_dir)
        .arg("--target")
        .arg("install")
        .arg("--parallel")
        .arg(parallel_jobs().to_string());
    if target_env_is("msvc") && cmake_generator() != "Ninja" {
        command.arg("--config").arg("Release");
    }
    command
}

fn parallel_jobs() -> usize {
    env_usize("CMAKE_BUILD_PARALLEL_LEVEL")
        .or_else(|| env_usize("NUM_JOBS"))
        .unwrap_or_else(default_llvm_parallel_jobs)
}

fn llvm_parallel_compile_jobs() -> usize {
    env_usize("BINLEX_LLVM_PARALLEL_COMPILE_JOBS")
        .or_else(|| env_usize("BINLEX_LLVM_PARALLEL_JOBS"))
        .unwrap_or_else(default_llvm_parallel_jobs)
}

fn llvm_parallel_link_jobs() -> usize {
    env_usize("BINLEX_LLVM_PARALLEL_LINK_JOBS").unwrap_or(1)
}

fn default_llvm_parallel_jobs() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(4)
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn detect_compiler(env_name: &str, candidates: &[&str]) -> PathBuf {
    if let Some(path) = std::env::var_os(env_name) {
        return PathBuf::from(path);
    }
    for candidate in candidates {
        if let Some(path) = which(candidate) {
            return path;
        }
    }
    panic!(
        "unable to locate a compiler for {}; tried {}",
        env_name,
        candidates.join(", ")
    );
}

fn run_checked(command: &mut Command, context: &str) {
    let program = command.get_program().to_os_string();
    let args = command.get_args().map(OsString::from).collect::<Vec<_>>();
    let status = command.status().unwrap_or_else(|error| {
        panic!(
            "{}: failed to spawn {}: {}",
            context,
            display_program(&program),
            error
        )
    });
    if !status.success() {
        panic!(
            "{}: command {} {} exited with status {}",
            context,
            display_program(&program),
            args.iter()
                .map(display_os_string)
                .collect::<Vec<_>>()
                .join(" "),
            status
        );
    }
}

fn display_program(program: &OsString) -> String {
    display_os_string(program)
}

fn display_os_string(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

fn which(binary: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for path in std::env::split_paths(&paths) {
        let candidate = path.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
        if target_os_is("windows") {
            let exe = path.join(format!("{binary}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

fn command_exists(binary: &str) -> bool {
    which(binary).is_some()
}

fn stale_lock_dir(lock_dir: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(lock_dir) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(elapsed) = modified.elapsed() else {
        return false;
    };
    elapsed > Duration::from_secs(30)
}
