extern crate anyhow;
extern crate cc;
#[macro_use]
extern crate lazy_static;
extern crate regex_lite;
extern crate semver;

use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use anyhow::Context as _;
use regex_lite::Regex;
use semver::Version;

const LLVM_TAG: &str = "llvmorg-22.1.3";
const LLVM_GIT_URL: &str = "https://github.com/llvm/llvm-project.git";

// Environment variables that can guide compilation
//
// When adding new ones, they should also be added to main() to force a
// rebuild if they are changed.
lazy_static! {
    /// A single path to search for LLVM in (containing bin/llvm-config)
    static ref ENV_LLVM_PREFIX: String =
        format!("LLVM_SYS_{}_PREFIX", env!("CARGO_PKG_VERSION_MAJOR"));

    /// If exactly "YES", ignore the version blocklist
    static ref ENV_IGNORE_BLOCKLIST: String =
        format!("LLVM_SYS_{}_IGNORE_BLOCKLIST", env!("CARGO_PKG_VERSION_MAJOR"));

    /// If set, enforce precise correspondence between crate and binary versions.
    static ref ENV_STRICT_VERSIONING: String =
        format!("LLVM_SYS_{}_STRICT_VERSIONING", env!("CARGO_PKG_VERSION_MAJOR"));

    /// If set, do not attempt to strip irrelevant options for llvm-config --cflags
    static ref ENV_NO_CLEAN_CFLAGS: String =
        format!("LLVM_SYS_{}_NO_CLEAN_CFLAGS", env!("CARGO_PKG_VERSION_MAJOR"));

    /// If set and targeting MSVC, force the debug runtime library
    static ref ENV_USE_DEBUG_MSVCRT: String =
        format!("LLVM_SYS_{}_USE_DEBUG_MSVCRT", env!("CARGO_PKG_VERSION_MAJOR"));

    /// If set, always link against libffi
    static ref ENV_FORCE_FFI: String =
        format!("LLVM_SYS_{}_FFI_WORKAROUND", env!("CARGO_PKG_VERSION_MAJOR"));
}

lazy_static! {
    /// LLVM version used by this version of the crate.
    static ref CRATE_VERSION: Version = {
        let crate_version = Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("Crate version is somehow not valid semver");
        Version {
            major: crate_version.major / 10,
            minor: crate_version.major % 10,
            .. crate_version
        }
    };
}

fn target_env_is(name: &str) -> bool {
    match env::var_os("CARGO_CFG_TARGET_ENV") {
        Some(s) => s == name,
        None => false,
    }
}

fn target_os_is(name: &str) -> bool {
    match env::var_os("CARGO_CFG_TARGET_OS") {
        Some(s) => s == name,
        None => false,
    }
}

fn target_abi_is(name: &str) -> bool {
    match env::var_os("CARGO_CFG_TARGET_ABI") {
        Some(s) => s == name,
        None => false,
    }
}

/// Try to find a version of llvm-config that is compatible with this crate.
///
/// If $LLVM_SYS_<VERSION>_PREFIX is set, look for llvm-config ONLY in there. The assumption is
/// that the user know best, and they want to link to a specific build or fork of LLVM.
///
/// If $LLVM_SYS_<VERSION>_PREFIX is NOT set, then look for llvm-config in $PATH.
///
/// Returns None on failure.
fn locate_llvm_config() -> Option<PathBuf> {
    if let Some(prefix) = env::var_os(&*ENV_LLVM_PREFIX) {
        return llvm_compatible_binary_name(&PathBuf::from(prefix).join("bin"));
    }

    let shared_prefix = shared_llvm_install_prefix();
    let shared_bin = shared_prefix.join("bin");
    if let Some(x) = llvm_compatible_binary_name(&shared_bin) {
        return Some(x);
    }

    bootstrap_shared_llvm(&shared_prefix);
    if let Some(x) = llvm_compatible_binary_name(&shared_bin) {
        return Some(x);
    }

    if let Some(x) = llvm_compatible_binary_name(Path::new("")) {
        return Some(x);
    }

    // For users of Homebrew, LLVM is located in a non-standard location and
    // typically not linked such that it appears in PATH. We try to handle that
    // here, but only if we didn't already find a working llvm-config in PATH.
    // This removes the need for fiddling around with LIBRARY_PATH or `brew
    // link`.
    if target_os_is("macos") {
        if let Some(p) = homebrew_prefix(Some(&format!("llvm@{}", CRATE_VERSION.major)))
            .or_else(|| homebrew_prefix(Some("llvm")))
        {
            return llvm_compatible_binary_name(&PathBuf::from(p).join("bin"));
        }
    }

    None
}

fn llvm_compatible_binary_name(prefix: &Path) -> Option<PathBuf> {
    for binary_name in llvm_config_binary_names() {
        let binary_name = prefix.join(binary_name);
        match llvm_version(&binary_name) {
            Ok(version) => {
                if is_compatible_llvm(&version) {
                    // Compatible version found. Nice.
                    return Some(binary_name);
                }
                // Version mismatch. Will try further searches, but warn that
                // we're not using the system one.
                println!(
                    "found LLVM version {} on PATH, but need {}",
                    version, *CRATE_VERSION
                );
            }
            Err(e) => {
                if e.downcast_ref::<io::Error>()
                    .map_or(false, |e| e.kind() == ErrorKind::NotFound)
                {
                    // Looks like we failed to execute any llvm-config. Keep
                    // searching.
                } else {
                    // Some other error, probably a weird failure. Give up.
                    panic!("Failed to search PATH for llvm-config: {}", e)
                }
            }
        }
    }

    None
}

/// Return an iterator over possible names for the llvm-config binary.
fn llvm_config_binary_names() -> impl Iterator<Item = String> {
    let base_names = [
        "llvm-config".into(),
        format!("llvm-config-{}", CRATE_VERSION.major),
        format!("llvm-config{}", CRATE_VERSION.major),
        format!("llvm{}-config", CRATE_VERSION.major),
        format!(
            "llvm-config-{}.{}",
            CRATE_VERSION.major, CRATE_VERSION.minor
        ),
        format!("llvm-config{}{}", CRATE_VERSION.major, CRATE_VERSION.minor),
    ];

    // On Windows, also search for llvm-config.exe
    if target_os_is("windows") {
        IntoIterator::into_iter(base_names)
            .flat_map(|name| [format!("{}.exe", name), name])
            .collect::<Vec<_>>()
    } else {
        base_names.to_vec()
    }
    .into_iter()
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

fn target_dir() -> PathBuf {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    out_dir
        .ancestors()
        .find(|path| path.file_name().and_then(|item| item.to_str()) == Some("target"))
        .expect("derive target dir from OUT_DIR")
        .to_path_buf()
}

fn bootstrap_shared_llvm(install_prefix: &Path) {
    let llvm_config_path = expected_llvm_config_path(install_prefix);
    if llvm_config_path.exists() {
        return;
    }

    let bootstrap_root = target_dir().join("llvm-bootstrap");
    let lock_dir = bootstrap_root.join("bootstrap.lock");
    std::fs::create_dir_all(&bootstrap_root).expect("create llvm bootstrap root");

    loop {
        match std::fs::create_dir(&lock_dir) {
            Ok(()) => break,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                if llvm_config_path.exists() {
                    return;
                }
                thread::sleep(Duration::from_secs(1));
            }
            Err(error) => panic!("failed to acquire llvm bootstrap lock: {}", error),
        }
    }

    let result = (|| {
        if llvm_config_path.exists() {
            return;
        }

        let source_root = target_dir().join("llvm-bootstrap").join("src");
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
        let build_dir = target_dir().join("llvm-bootstrap").join(format!(
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
            .arg("-DLLVM_TARGETS_TO_BUILD=AArch64;X86")
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

fn parallel_jobs() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
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

fn display_program(program: &OsString) -> String {
    program.to_string_lossy().into_owned()
}

fn display_args(args: &[OsString]) -> String {
    args.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Check whether the given version of LLVM is blocklisted,
/// returning `Some(reason)` if it is.
fn is_blocklisted_llvm(llvm_version: &Version) -> Option<&'static str> {
    static BLOCKLIST: &[(u64, u64, u64, &str)] = &[];

    if let Some(x) = env::var_os(&*ENV_IGNORE_BLOCKLIST) {
        if &x == "YES" {
            println!(
                "cargo:warning=ignoring blocklist entry for LLVM {}",
                llvm_version
            );
            return None;
        } else {
            println!(
                "cargo:warning={} is set but not exactly \"YES\"; blocklist is still honored",
                *ENV_IGNORE_BLOCKLIST
            );
        }
    }

    for &(major, minor, patch, reason) in BLOCKLIST.iter() {
        let bad_version = Version {
            major,
            minor,
            patch,
            pre: semver::Prerelease::EMPTY,
            build: semver::BuildMetadata::EMPTY,
        };

        if &bad_version == llvm_version {
            return Some(reason);
        }
    }
    None
}

/// Check whether the given LLVM version is compatible with this version of
/// the crate.
fn is_compatible_llvm(llvm_version: &Version) -> bool {
    if let Some(reason) = is_blocklisted_llvm(llvm_version) {
        println!(
            "found LLVM {}, which is blocklisted: {}",
            llvm_version, reason
        );
        return false;
    }

    let strict =
        env::var_os(&*ENV_STRICT_VERSIONING).is_some() || cfg!(feature = "strict-versioning");
    if strict {
        llvm_version.major == CRATE_VERSION.major && llvm_version.minor == CRATE_VERSION.minor
    } else {
        llvm_version.major >= CRATE_VERSION.major
            || (llvm_version.major == CRATE_VERSION.major
                && llvm_version.minor >= CRATE_VERSION.minor)
    }
}

/// Invoke the specified binary as llvm-config.
fn llvm_config<I, S>(binary: &Path, args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    llvm_config_ex(binary, args).expect("Surprising failure from llvm-config")
}

/// Invoke the specified binary as llvm-config.
///
/// Explicit version of the `llvm_config` function that bubbles errors
/// up.
fn llvm_config_ex<I, S>(binary: &Path, args: I) -> anyhow::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(binary);
    (|| {
        let Output {
            status,
            stdout,
            stderr,
        } = cmd.args(args).output()?;
        let stdout = String::from_utf8(stdout).context("stdout")?;
        let stderr = String::from_utf8(stderr).context("stderr")?;
        if status.success() {
            Ok(stdout)
        } else {
            Err(anyhow::anyhow!(
                "status={status}\nstdout={}\nstderr={}",
                stdout.trim(),
                stderr.trim()
            ))
        }
    })()
    .with_context(|| format!("{cmd:?}"))
}

/// Get the LLVM version using llvm-config.
fn llvm_version(binary: &Path) -> anyhow::Result<Version> {
    let version_str = llvm_config_ex(binary, ["--version"])?;

    // LLVM isn't really semver and uses version suffixes to build
    // version strings like '3.8.0svn', so limit what we try to parse
    // to only the numeric bits.
    let re = Regex::new(r"^(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))??").unwrap();
    let c = re.captures(&version_str).ok_or_else(|| {
        anyhow::anyhow!(
            "could not determine LLVM version from llvm-config. Version string: {version_str}"
        )
    })?;

    // some systems don't have a patch number but Version wants it so we just append .0 if it isn't
    // there
    let major = c.name("major").unwrap().as_str().parse().context("major")?;
    let minor = c.name("minor").unwrap().as_str().parse().context("minor")?;
    let patch = match c.name("patch") {
        None => 0,
        Some(patch) => patch.as_str().parse().context("patch")?,
    };
    Ok(Version::new(major, minor, patch))
}

/// Get the names of the dylibs required by LLVM, including the C++ standard
/// library.
fn get_system_libraries(llvm_config_path: &Path, kind: LibraryKind) -> Vec<String> {
    let link_arg = match kind {
        LibraryKind::Static => "--link-static",
        LibraryKind::Dynamic => "--link-shared",
    };

    llvm_config(llvm_config_path, ["--system-libs", link_arg])
        .split(&[' ', '\n'] as &[char])
        .filter(|s| !s.is_empty())
        .map(|flag| {
            if target_env_is("msvc") {
                // Same as --libnames, foo.lib
                flag.strip_suffix(".lib").unwrap_or_else(|| {
                    panic!(
                        "system library '{}' does not appear to be a MSVC library file",
                        flag
                    )
                })
            } else {
                if let Some(flag) = flag.strip_prefix("-l") {
                    // Linker flags style, -lfoo
                    if target_os_is("macos") {
                        // .tdb libraries are "text-based stub" files that provide lists of symbols,
                        // which refer to libraries shipped with a given system and aren't shipped
                        // as part of the corresponding SDK. They're named like the underlying
                        // library object, including the 'lib' prefix that we need to strip.
                        if let Some(flag) = flag
                            .strip_prefix("lib")
                            .and_then(|flag| flag.strip_suffix(".tbd"))
                        {
                            return flag;
                        }
                    }

                    if let Some(i) = flag.find(".so.") {
                        // On some distributions (OpenBSD, perhaps others), we get sonames
                        // like "-lz.so.7.0". Correct those by pruning the file extension
                        // and library version.
                        return &flag[..i];
                    }
                    return flag;
                }

                let maybe_lib = Path::new(flag);
                if maybe_lib.is_file() {
                    // Library on disk, likely an absolute path to a .so. We'll add its location to
                    // the library search path and specify the file as a link target.
                    println!(
                        "cargo:rustc-link-search={}",
                        maybe_lib.parent().unwrap().display()
                    );

                    // Expect a file named something like libfoo.so, or with a version libfoo.so.1.
                    // Trim everything after and including the last .so and remove the leading 'lib'
                    let soname = maybe_lib
                        .file_name()
                        .unwrap()
                        .to_str()
                        .expect("Library filename must be a valid string");

                    // Check for any valid library filename, even if it's a different kind from the
                    // one we asked for. Some configurations give us a path to a static archive,
                    // even when we're asking for shared libraries.
                    [LibraryKind::Dynamic, LibraryKind::Static]
                        .iter()
                        .filter_map(|&kind| {
                            if let Some((stem, _rest)) = soname.rsplit_once(kind.file_extension()) {
                                Some(stem.strip_prefix("lib").unwrap_or_else(|| {
                                    panic!(
                                        "system library '{}' does not have a 'lib' prefix",
                                        soname
                                    )
                                }))
                            } else {
                                None
                            }
                        })
                        .next()
                        .unwrap_or_else(|| {
                            panic!(
                                "Filename '{}' does not appear to refer to a library file",
                                soname
                            )
                        })
                } else {
                    panic!(
                        "Unable to parse result of llvm-config --system-libs: {}",
                        flag
                    )
                }
            }
        })
        .chain(get_system_libcpp())
        .map(str::to_owned)
        .collect()
}

/// Return additional linker search paths that should be used but that are not discovered
/// by other means.
///
/// In particular, this should include only directories that are known from platform-specific
/// knowledge that aren't otherwise discovered from either `llvm-config` or a linked library
/// that includes an absolute path.
fn get_system_library_dirs() -> impl IntoIterator<Item = String> {
    let mut system_library_dirs = Vec::new();

    // Add the directories provided through the environment variable.
    if let Some(dirs) = option_env!("LLVM_SYS_SYSTEM_LIBRARY_DIRS") {
        system_library_dirs.extend(dirs.split(':').map(|s| s.to_string()));
    }

    if target_os_is("openbsd") || target_os_is("freebsd") {
        system_library_dirs.push("/usr/local/lib".to_string());
    } else if target_os_is("macos") {
        if let Some(p) = homebrew_prefix(None) {
            system_library_dirs.push(format!("{}/lib", p));
        }
    } else if target_os_is("linux") && cfg!(target_feature = "crt-static") {
        // When linking statically on Linux, we need to provide the directory
        // with system-wide static libraries explicitly.
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "powerpc64",
            target_arch = "aarch64"
        ))]
        {
            system_library_dirs.push("/lib64".to_string());
            system_library_dirs.push("/usr/lib64".to_string());
            system_library_dirs.push("/usr/local/lib64".to_string());
        }
        system_library_dirs.push("/lib".to_string());
        system_library_dirs.push("/usr/lib".to_string());
        system_library_dirs.push("/usr/local/lib".to_string());
    }

    system_library_dirs
}

fn homebrew_prefix(name: Option<&str>) -> Option<String> {
    let mut cmd = Command::new("brew");

    cmd.arg("--prefix");

    if let Some(name) = name {
        cmd.arg(name);
    }

    cmd.output()
        .ok()
        .filter(|o| !o.stdout.is_empty())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|val| val.trim().to_string())
}

/// Get the library that must be linked for C++, if any.
fn get_system_libcpp() -> Option<&'static str> {
    if let Some(libcpp) = option_env!("CXXSTDLIB").or(option_env!("LLVM_SYS_LIBCPP")) {
        // Use the library defined by the caller, if provided.
        // CXXSTDLIB is a de-facto standard used by cc-rs.
        Some(libcpp)
    } else if target_env_is("msvc") {
        // MSVC doesn't need an explicit one.
        None
    } else if target_os_is("macos") {
        // On OS X 10.9 and later, LLVM's libc++ is the default. On earlier
        // releases GCC's libstdc++ is default. Unfortunately we can't
        // reasonably detect which one we need (on older ones libc++ is
        // available and can be selected with -stdlib=lib++), so assume the
        // latest, at the cost of breaking the build on older OS releases
        // when LLVM was built against libstdc++.
        Some("c++")
    } else if target_os_is("freebsd") || target_os_is("openbsd") {
        Some("c++")
    } else if target_abi_is("llvm") {
        // These are `*-pc-windows-gnullvm` targets, which are based on LLVM
        // toolchain, so libc++ is the only cxx std library here
        Some("c++")
    } else {
        // Otherwise assume GCC's libstdc++.
        // This assumption is probably wrong on some platforms, but it can be
        // always overwritten through `CXXSTDLIB` variable.
        Some("stdc++")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LibraryKind {
    Static,
    Dynamic,
}

impl LibraryKind {
    pub fn string(&self) -> &'static str {
        match self {
            LibraryKind::Static => "static",
            LibraryKind::Dynamic => "dylib",
        }
    }

    /// Return the file extension associated with a library kind for the target platform.
    ///
    /// The returned extension includes a leading '.', like ".so".
    pub fn file_extension(&self) -> &'static str {
        match self {
            LibraryKind::Dynamic => {
                if target_os_is("macos") {
                    ".dylib"
                } else {
                    ".so"
                }
            }
            LibraryKind::Static => ".a",
        }
    }
}

/// Get the names of libraries to link against, along with whether it is static or shared library.
fn get_link_libraries(
    llvm_config_path: &Path,
    preferences: &LinkingPreferences,
) -> (LibraryKind, Vec<String>) {
    // Using --libnames in conjunction with --libdir is particularly important
    // for MSVC when LLVM is in a path with spaces, but it is generally less of
    // a hack than parsing linker flags output from --libs and --ldflags.

    fn get_link_libraries_impl(
        llvm_config_path: &Path,
        kind: LibraryKind,
    ) -> anyhow::Result<String> {
        if target_env_is("msvc") && kind == LibraryKind::Dynamic {
            // Upstream work on support: https://github.com/llvm/llvm-project/issues/109483
            anyhow::bail!("Dynamic linking to LLVM is not currently supported on Windows");
        }

        let link_arg = match kind {
            LibraryKind::Static => "--link-static",
            LibraryKind::Dynamic => "--link-shared",
        };
        llvm_config_ex(llvm_config_path, ["--libnames", link_arg])
    }

    let LinkingPreferences {
        prefer_static,
        force,
    } = preferences;
    let one = [*prefer_static];
    let both = [*prefer_static, !*prefer_static];

    let preferences = if *force { &one[..] } else { &both[..] }
        .iter()
        .map(|is_static| {
            if *is_static {
                LibraryKind::Static
            } else {
                LibraryKind::Dynamic
            }
        });

    for kind in preferences {
        match get_link_libraries_impl(llvm_config_path, kind) {
            Ok(s) => return (kind, extract_library(&s, kind)),
            Err(err) => {
                println!(
                    "failed to get {} libraries from llvm-config: {err:?}",
                    kind.string()
                )
            }
        }
    }

    panic!("failed to get linking libraries from llvm-config",);
}

fn extract_library(s: &str, kind: LibraryKind) -> Vec<String> {
    s.split(&[' ', '\n'] as &[char])
        .filter(|s| !s.is_empty())
        .map(|name| {
            // --libnames gives library filenames. Extract only the name that
            // we need to pass to the linker.
            match kind {
                LibraryKind::Static => {
                    // Match static library
                    if let Some(name) = name
                        .strip_prefix("lib")
                        .and_then(|name| name.strip_suffix(".a"))
                    {
                        // Unix (Linux/Mac)
                        // libLLVMfoo.a
                        name
                    } else if let Some(name) = name.strip_suffix(".lib") {
                        // Windows
                        // LLVMfoo.lib
                        name
                    } else {
                        panic!("'{}' does not look like a static library name", name)
                    }
                }
                LibraryKind::Dynamic => {
                    // Match shared library
                    if let Some(name) = name
                        .strip_prefix("lib")
                        .and_then(|name| name.strip_suffix(".dylib"))
                    {
                        // Mac
                        // libLLVMfoo.dylib
                        name
                    } else if let Some(name) = name
                        .strip_prefix("lib")
                        .and_then(|name| name.strip_suffix(".so"))
                    {
                        // Linux
                        // libLLVMfoo.so
                        name
                    } else if let Some(name) = IntoIterator::into_iter([".dll", ".lib"])
                        .find_map(|suffix| name.strip_suffix(suffix))
                    {
                        // Windows
                        // LLVMfoo.{dll,lib}
                        name
                    } else {
                        panic!("'{}' does not look like a shared library name", name)
                    }
                }
            }
            .to_string()
        })
        .collect::<Vec<String>>()
}

#[derive(Debug, Clone, Copy)]
struct LinkingPreferences {
    /// Prefer static linking over dynamic linking.
    prefer_static: bool,
    /// Force the use of the preferred kind of linking.
    force: bool,
}

impl LinkingPreferences {
    fn init() -> LinkingPreferences {
        let prefer_static = cfg!(feature = "prefer-static");
        let prefer_dynamic = cfg!(feature = "prefer-dynamic");
        let force_static = cfg!(feature = "force-static");
        let force_dynamic = cfg!(feature = "force-dynamic");

        // more than one preference is an error
        if [prefer_static, prefer_dynamic, force_static, force_dynamic]
            .iter()
            .filter(|&&x| x)
            .count()
            > 1
        {
            panic!(
                "Only one of the features `prefer-static`, `prefer-dynamic`, `force-static`, \
                 `force-dynamic` can be enabled at once"
            );
        }

        // if no preference is given, default to prefer static linking
        let prefer_static = prefer_static || !(prefer_dynamic || force_static || force_dynamic);

        LinkingPreferences {
            prefer_static: force_static || prefer_static,
            force: force_static || force_dynamic,
        }
    }
}

fn get_llvm_cflags(llvm_config_path: &Path) -> String {
    let output = llvm_config(llvm_config_path, ["--cflags"]);

    // llvm-config includes cflags from its own compilation with --cflags that
    // may not be relevant to us. In particularly annoying cases, these might
    // include flags that aren't understood by the default compiler we're
    // using. Unless requested otherwise, clean CFLAGS of options that are
    // known to be possibly-harmful.
    let no_clean = env::var_os(&*ENV_NO_CLEAN_CFLAGS).is_some();
    if no_clean || target_env_is("msvc") {
        // MSVC doesn't accept -W... options, so don't try to strip them and
        // possibly strip something that should be retained. Also do nothing if
        // the user requests it.
        return output;
    }

    output
        .split(&[' ', '\n'][..])
        .filter(|word| !word.starts_with("-W"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_llvm_debug(llvm_config_path: &Path) -> bool {
    // Has to be either Debug or Release
    llvm_config(llvm_config_path, ["--build-mode"]).contains("Debug")
}

fn main() {
    // Behavior can be significantly affected by these vars.
    println!("cargo:rerun-if-env-changed={}", &*ENV_LLVM_PREFIX);
    if let Ok(path) = env::var(&*ENV_LLVM_PREFIX) {
        println!("cargo:rerun-if-changed={}", path);
    }

    println!("cargo:rerun-if-env-changed={}", &*ENV_IGNORE_BLOCKLIST);
    println!("cargo:rerun-if-env-changed={}", &*ENV_STRICT_VERSIONING);
    println!("cargo:rerun-if-env-changed={}", &*ENV_NO_CLEAN_CFLAGS);
    println!("cargo:rerun-if-env-changed={}", &*ENV_USE_DEBUG_MSVCRT);
    println!("cargo:rerun-if-env-changed={}", &*ENV_FORCE_FFI);

    if cfg!(feature = "no-llvm-linking") && cfg!(feature = "disable-alltargets-init") {
        // exit early as we don't need to do anything and llvm-config isn't needed at all
        return;
    }

    let llvm_config_path = match locate_llvm_config() {
        None => {
            println!("cargo:rustc-cfg=LLVM_SYS_NOT_FOUND");
            return;
        }
        Some(llvm_config_path) => llvm_config_path,
    };

    // Build the extra wrapper functions.
    if !cfg!(feature = "disable-alltargets-init") {
        std::env::set_var("CFLAGS", get_llvm_cflags(&llvm_config_path));
        cc::Build::new()
            .file("wrappers/target.c")
            .compile("targetwrappers");
    }

    if cfg!(feature = "no-llvm-linking") {
        return;
    }

    let libdir = llvm_config(&llvm_config_path, ["--libdir"]);

    // Export information to other crates
    println!("cargo:config_path={}", llvm_config_path.display()); // will be DEP_LLVM_CONFIG_PATH
    println!("cargo:libdir={}", libdir); // DEP_LLVM_LIBDIR

    let preferences = LinkingPreferences::init();

    // Link LLVM libraries
    println!("cargo:rustc-link-search=native={}", libdir);
    for link_search_dir in get_system_library_dirs() {
        println!("cargo:rustc-link-search=native={}", link_search_dir);
    }
    // We need to take note of what kind of libraries we linked to, so that
    // we can link to the same kind of system libraries
    let (kind, libs) = get_link_libraries(&llvm_config_path, &preferences);
    for name in libs {
        println!("cargo:rustc-link-lib={}={}", kind.string(), name);
    }

    // Link system libraries
    // We get the system libraries based on the kind of LLVM libraries we link to, but we link to
    // system libs based on the target environment.
    let sys_lib_kind = if target_os_is("windows") {
        LibraryKind::Dynamic
    } else if cfg!(target_feature = "crt-static") {
        LibraryKind::Static
    } else {
        LibraryKind::Dynamic
    };
    for name in get_system_libraries(&llvm_config_path, kind) {
        println!("cargo:rustc-link-lib={}={}", sys_lib_kind.string(), name);
    }

    let use_debug_msvcrt = env::var_os(&*ENV_USE_DEBUG_MSVCRT).is_some();
    if target_env_is("msvc") && (use_debug_msvcrt || is_llvm_debug(&llvm_config_path)) {
        println!("cargo:rustc-link-lib=msvcrtd");
    }

    // Link libffi if the user requested this workaround.
    // See https://bitbucket.org/tari/llvm-sys.rs/issues/12/
    let force_ffi = env::var_os(&*ENV_FORCE_FFI).is_some();
    if force_ffi {
        println!("cargo:rustc-link-lib=dylib=ffi");
    }
}
