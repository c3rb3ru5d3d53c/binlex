use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

const LLVM_TAG: &str = "llvmorg-22.1.3";
const LLVM_GIT_URL: &str = "https://github.com/llvm/llvm-project.git";
const STATIC_COMPONENTS: &[&str] = &[
    "mc",
    "mcparser",
    "support",
    "target",
    "targetparser",
    "x86asmparser",
    "x86desc",
    "x86info",
    "x86codegen",
    "aarch64asmparser",
    "aarch64desc",
    "aarch64info",
    "aarch64codegen",
];

fn main() {
    println!("cargo:rerun-if-changed=native/assembler.cpp");
    println!("cargo:rerun-if-changed=native/assembler.hpp");
    if target_env_is("gnu") && !target_os_is("macos") {
        println!("cargo:rustc-link-arg=-Wl,--exclude-libs,ALL");
    }

    let llvm = load_shared_llvm();
    println!(
        "cargo:rustc-env=LLVM_ASM_HOST_TRIPLE={}",
        llvm_config(&llvm.llvm_config, &["--host-target"]).trim()
    );

    compile_shim(&llvm);
    link_static_llvm(&llvm);
    if let Some(cpp_stdlib) = cpp_stdlib() {
        println!("cargo:rustc-link-lib=dylib={cpp_stdlib}");
    }
}

#[derive(Clone, Debug)]
struct LlvmInstall {
    llvm_config: PathBuf,
    includedir: String,
    libdir: String,
    cxxflags: String,
}

fn ensure_static_llvm() -> LlvmInstall {
    if let Some(llvm_config_path) = env_llvm_config_path() {
        if supports_static(&llvm_config_path) {
            return load_llvm_install(llvm_config_path);
        }
    }

    let install_prefix = shared_llvm_install_prefix();
    let llvm_config_path = expected_llvm_config_path(&install_prefix);
    if !llvm_install_ready(&install_prefix) {
        bootstrap_shared_llvm(&install_prefix);
    }
    if !supports_static(&llvm_config_path) {
        panic!(
            "static llvm build completed but {} does not provide the required archives",
            llvm_config_path.display()
        );
    }

    load_llvm_install(llvm_config_path)
}

fn load_shared_llvm() -> LlvmInstall {
    ensure_static_llvm()
}

fn bootstrap_shared_llvm(install_prefix: &Path) {
    if llvm_install_ready(install_prefix) {
        return;
    }

    let bootstrap_root = target_dir().join("llvm-bootstrap");
    let lock_dir = bootstrap_root.join("bootstrap.lock");
    std::fs::create_dir_all(&bootstrap_root).expect("create llvm bootstrap root");

    loop {
        match std::fs::create_dir(&lock_dir) {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if llvm_install_ready(install_prefix) {
                    return;
                }
                thread::sleep(Duration::from_secs(1));
            }
            Err(error) => panic!("failed to acquire llvm bootstrap lock: {}", error),
        }
    }

    let result = (|| {
        if llvm_install_ready(install_prefix) {
            return;
        }

        let source_root = bootstrap_root.join("src");
        let repo_root = source_root.join("llvm-project");
        let llvm_source = repo_root.join("llvm");
        if !llvm_source.exists() {
            std::fs::create_dir_all(&source_root).expect("create llvm source root");
            run_checked(
                Command::new("git")
                    .arg("clone")
                    .arg("--depth=1")
                    .arg("--branch")
                    .arg(LLVM_TAG)
                    .arg("--single-branch")
                    .arg(LLVM_GIT_URL)
                    .arg(&repo_root),
                "clone llvm-project for shared llvm bootstrap",
            );
        }

        let generator = cmake_generator();
        let build_dir = bootstrap_root.join(format!(
            "build-{}",
            generator.to_ascii_lowercase().replace(' ', "-")
        ));
        std::fs::create_dir_all(&build_dir).expect("create llvm build dir");
        std::fs::create_dir_all(install_prefix).expect("create llvm install dir");

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
            .arg("-DLLVM_ENABLE_PROJECTS=")
            .arg("-DLLVM_ENABLE_ASSERTIONS=OFF")
            .arg("-DLLVM_ENABLE_LIBXML2=OFF")
            .arg("-DLLVM_ENABLE_TERMINFO=OFF")
            .arg("-DLLVM_ENABLE_LIBEDIT=OFF")
            .arg("-DLLVM_ENABLE_ZSTD=OFF")
            .arg("-DLLVM_ENABLE_ZLIB=OFF")
            .arg("-DCMAKE_SKIP_INSTALL_RPATH=ON")
            .arg("-DCMAKE_SKIP_RPATH=ON");
        configure_bootstrap_compilers(&mut configure);
        run_checked(&mut configure, "configure shared llvm bootstrap");
        let mut build = cmake_build_command(&build_dir);
        run_checked(&mut build, "build shared llvm bootstrap");
        assert!(
            llvm_install_ready(install_prefix),
            "shared llvm bootstrap completed without installing llvm-c headers into {}",
            install_prefix.display()
        );
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

fn compile_shim(llvm: &LlvmInstall) {
    let mut build = cc::Build::new();
    build.cpp(true);
    build.file("native/assembler.cpp");
    for include_dir in llvm_include_dirs(llvm) {
        build.include(&include_dir);
        if target_env_is("msvc") {
            build.flag(&format!("/I{}", include_dir.display()));
        } else {
            build.flag_if_supported(&format!("-isystem{}", include_dir.display()));
        }
    }
    if target_env_is("msvc") {
        build.flag_if_supported("/std:c++17");
    } else {
        build.flag("-std=c++17");
    }
    build.flag_if_supported("-fno-exceptions");
    build.flag_if_supported("-fno-rtti");
    build.flag_if_supported("-fvisibility=hidden");
    build.flag_if_supported("-fvisibility-inlines-hidden");
    build.flag_if_supported("-Wno-unused-parameter");
    for flag in shell_words(&llvm.cxxflags) {
        if target_env_is("msvc") {
            continue;
        }
        if flag.starts_with("-W") {
            continue;
        }
        if flag == "-std=c++17" {
            continue;
        }
        build.flag(&flag);
    }
    build.compile("binlex_llvm_assembler");
}

fn llvm_include_dirs(llvm: &LlvmInstall) -> Vec<PathBuf> {
    let mut include_dirs = vec![PathBuf::from(llvm.includedir.trim())];
    let bootstrap_root = target_dir().join("llvm-bootstrap");
    let source_include = bootstrap_root
        .join("src")
        .join("llvm-project")
        .join("llvm")
        .join("include");
    if source_include.exists() {
        include_dirs.push(source_include);
    }
    if let Ok(entries) = std::fs::read_dir(&bootstrap_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.starts_with("build-") {
                continue;
            }
            let build_include = path.join("include");
            if build_include.exists() {
                include_dirs.push(build_include);
            }
        }
    }
    include_dirs.sort();
    include_dirs.dedup();
    include_dirs
}

fn link_static_llvm(llvm: &LlvmInstall) {
    let mut args = vec!["--libnames", "--link-static"];
    args.extend(STATIC_COMPONENTS);
    let libnames = llvm_config_checked(
        &llvm.llvm_config,
        &args,
        "static llvm archives missing for llvm-asm",
    );
    println!("cargo:rustc-link-search=native={}", llvm.libdir.trim());
    for lib in shell_words(&libnames) {
        if is_static_library_name(&lib) {
            println!(
                "cargo:rustc-link-lib=static={}",
                normalize_library_name(&lib)
            );
        }
    }
    for lib in shell_words(&llvm_config(
        &llvm.llvm_config,
        &["--system-libs", "--link-static"],
    )) {
        emit_system_lib(llvm, &lib);
    }
}

fn load_llvm_install(llvm_config_path: PathBuf) -> LlvmInstall {
    LlvmInstall {
        includedir: llvm_config(&llvm_config_path, &["--includedir"]),
        libdir: llvm_config(&llvm_config_path, &["--libdir"]),
        cxxflags: llvm_config(&llvm_config_path, &["--cxxflags"]),
        llvm_config: llvm_config_path,
    }
}

fn supports_static(llvm_config_path: &Path) -> bool {
    let mut args = vec!["--libnames", "--link-static"];
    args.extend(STATIC_COMPONENTS);
    llvm_config_try(llvm_config_path, &args).is_ok()
}

fn llvm_config(llvm_config_path: &Path, args: &[&str]) -> String {
    llvm_config_checked(llvm_config_path, args, "llvm-config invocation failed")
}

fn llvm_config_checked(llvm_config_path: &Path, args: &[&str], context: &str) -> String {
    llvm_config_try(llvm_config_path, args).unwrap_or_else(|error| panic!("{}: {}", context, error))
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

fn target_dir() -> PathBuf {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    out_dir
        .ancestors()
        .find(|path| path.file_name().and_then(|item| item.to_str()) == Some("target"))
        .expect("derive target dir from OUT_DIR")
        .to_path_buf()
}

fn shared_llvm_install_prefix() -> PathBuf {
    target_dir().join("llvm-bootstrap").join("install")
}

fn expected_llvm_config_path(install_prefix: &Path) -> PathBuf {
    install_prefix.join("bin").join(if target_os_is("windows") {
        "llvm-config.exe"
    } else {
        "llvm-config"
    })
}

fn llvm_install_ready(install_prefix: &Path) -> bool {
    expected_llvm_config_path(install_prefix).exists()
        && install_prefix
            .join("include")
            .join("llvm-c")
            .join("Target.h")
            .exists()
}

fn env_llvm_config_path() -> Option<PathBuf> {
    let prefix = std::env::var_os("LLVM_SYS_221_PREFIX")?;
    Some(expected_llvm_config_path(&PathBuf::from(prefix)))
}

fn parallel_jobs() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
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

fn emit_system_lib(llvm: &LlvmInstall, flag: &str) {
    if let Some(name) = flag.strip_prefix("-l") {
        emit_external_system_search_paths(llvm, name);
        println!("cargo:rustc-link-lib={}", name);
    } else if is_static_library_name(flag) {
        println!(
            "cargo:rustc-link-lib=static={}",
            normalize_library_name(flag)
        );
    } else if flag.ends_with(".lib") {
        println!("cargo:rustc-link-lib={}", normalize_library_name(flag));
    } else if let Some(path) = flag.strip_prefix("-L") {
        println!("cargo:rustc-link-search=native={}", path);
    }
}

fn emit_external_system_search_paths(llvm: &LlvmInstall, name: &str) {
    let mut search_paths = Vec::new();
    let llvm_libdir = PathBuf::from(llvm.libdir.trim());
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

fn is_static_library_name(value: &str) -> bool {
    value.ends_with(".a")
        || (target_env_is("msvc") && value.ends_with(".lib") && value.starts_with("LLVM"))
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
            "{}: {} {} exited with status {}",
            context,
            display_program(&program),
            display_args(&args),
            status
        );
    }
}

fn command_exists(program: &str) -> bool {
    which(program).is_some()
}

fn which(program: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&paths) {
        let candidate = entry.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn display_program(program: &OsString) -> String {
    program.to_string_lossy().into_owned()
}

fn display_args(args: &[OsString]) -> String {
    args.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}
