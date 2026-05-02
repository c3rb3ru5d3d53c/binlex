use object::{Object, ObjectSection, SectionKind};
use std::error::Error as StdError;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::c_char;

const START_MARKER: &[u8] = b"\x42\x49\x4e\x4c\x45\x58\x5f\x41\x53\x4d\x5f\x53\x54\x41\x52\x54";
const END_MARKER: &[u8] = b"\x42\x49\x4e\x4c\x45\x58\x5f\x41\x53\x4d\x5f\x45\x4e\x44\x5f\x5f";
const LLVM_HOST_TRIPLE: &str = env!("LLVM_ASM_HOST_TRIPLE");

unsafe extern "C" {
    fn binlex_llvm_assemble_to_object(
        triple: *const c_char,
        cpu: *const c_char,
        assembly: *const c_char,
        bytes: *mut *mut u8,
        length: *mut usize,
        error: *mut *mut c_char,
    ) -> bool;
    fn binlex_llvm_free_bytes(bytes: *mut u8);
    fn binlex_llvm_free_error(error: *mut c_char);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Architecture {
    AMD64,
    I386,
    ARM64,
}

#[derive(Debug)]
pub enum Error {
    UnsupportedArchitecture(Architecture),
    AssembleFailed(String),
    ObjectParseFailed(String),
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture(architecture) => {
                write!(f, "unsupported assembler architecture: {:?}", architecture)
            }
            Self::AssembleFailed(message) => write!(f, "assembly failed: {}", message),
            Self::ObjectParseFailed(message) => write!(f, "object parse failed: {}", message),
            Self::Internal(message) => write!(f, "assembler internal error: {}", message),
        }
    }
}

impl StdError for Error {}

pub struct Assembler {
    architecture: Architecture,
}

impl Assembler {
    pub fn new(architecture: Architecture) -> Result<Self, Error> {
        match architecture {
            Architecture::AMD64 | Architecture::I386 | Architecture::ARM64 => {
                Ok(Self { architecture })
            }
        }
    }

    pub fn assemble(&self, address: u64, text: &str) -> Result<Vec<u8>, Error> {
        let wrapped = self.wrap_assembly(address, text);
        let triple = CString::new(target_triple(self.architecture)?)
            .map_err(|_| Error::Internal("invalid llvm target triple".to_string()))?;
        let cpu = CString::new("generic")
            .map_err(|_| Error::Internal("invalid llvm target cpu".to_string()))?;
        let wrapped = CString::new(wrapped)
            .map_err(|_| Error::Internal("assembly text contains NUL byte".to_string()))?;

        let mut object_bytes = std::ptr::null_mut();
        let mut object_length = 0usize;
        let mut error = std::ptr::null_mut();

        let success = unsafe {
            binlex_llvm_assemble_to_object(
                triple.as_ptr(),
                cpu.as_ptr(),
                wrapped.as_ptr(),
                &mut object_bytes,
                &mut object_length,
                &mut error,
            )
        };

        if !success {
            let message = if error.is_null() {
                "llvm assembler reported an unknown error".to_string()
            } else {
                let result = unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned();
                unsafe {
                    binlex_llvm_free_error(error);
                }
                result
            };
            return Err(Error::AssembleFailed(message));
        }

        if object_bytes.is_null() {
            return Err(Error::Internal(
                "llvm assembler returned a null object buffer".to_string(),
            ));
        }

        let object = unsafe {
            let data = std::slice::from_raw_parts(object_bytes, object_length).to_vec();
            binlex_llvm_free_bytes(object_bytes);
            data
        };

        Self::extract_bytes(&object)
    }

    fn wrap_assembly(&self, address: u64, text: &str) -> String {
        let mut result = String::new();
        result.push_str(".text\n");
        result.push_str(&format!(".org 0x{address:x}\n"));
        if matches!(self.architecture, Architecture::AMD64 | Architecture::I386) {
            result.push_str(".intel_syntax noprefix\n");
        }
        result.push_str(&render_marker(".byte", START_MARKER));
        result.push('\n');
        result.push_str(&normalize_assembly(text));
        result.push('\n');
        result.push_str(&render_marker(".byte", END_MARKER));
        result.push('\n');
        result
    }

    fn extract_bytes(object_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let file = object::File::parse(object_bytes)
            .map_err(|error| Error::ObjectParseFailed(error.to_string()))?;

        for section in file.sections() {
            if section.kind() != SectionKind::Text {
                continue;
            }
            let data = section
                .data()
                .map_err(|error| Error::ObjectParseFailed(error.to_string()))?;
            let Some(start) = find_subsequence(data, START_MARKER) else {
                continue;
            };
            let body = &data[start + START_MARKER.len()..];
            let Some(end) = find_subsequence(body, END_MARKER) else {
                return Err(Error::ObjectParseFailed(
                    "assembly marker end not found".to_string(),
                ));
            };
            return Ok(body[..end].to_vec());
        }

        Err(Error::ObjectParseFailed(
            "assembly marker section not found".to_string(),
        ))
    }
}

fn normalize_assembly(text: &str) -> String {
    text.replace(';', "\n")
}

fn render_marker(directive: &str, bytes: &[u8]) -> String {
    format!(
        "{} {}",
        directive,
        bytes
            .iter()
            .map(|byte| format!("0x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn target_triple(architecture: Architecture) -> Result<String, Error> {
    let suffix = LLVM_HOST_TRIPLE
        .split_once('-')
        .map(|(_, suffix)| suffix)
        .unwrap_or("unknown-unknown");
    let architecture = match architecture {
        Architecture::AMD64 => "x86_64",
        Architecture::I386 => "i386",
        Architecture::ARM64 => "aarch64",
    };
    Ok(format!("{architecture}-{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::{Architecture, Assembler};

    #[test]
    fn assemble_amd64_intel_bytes() {
        let assembler = Assembler::new(Architecture::AMD64).expect("assembler");
        let bytes = assembler
            .assemble(0, "xor eax, eax; ret")
            .expect("assemble");
        assert_eq!(bytes, vec![0x31, 0xc0, 0xc3]);
    }

    #[test]
    fn assemble_i386_intel_bytes() {
        let assembler = Assembler::new(Architecture::I386).expect("assembler");
        let bytes = assembler
            .assemble(0, "xor eax, eax; ret")
            .expect("assemble");
        assert_eq!(bytes, vec![0x31, 0xc0, 0xc3]);
    }

    #[test]
    fn invalid_instruction_returns_error() {
        let assembler = Assembler::new(Architecture::AMD64).expect("assembler");
        let error = assembler
            .assemble(0, "definitely_not_an_instruction")
            .expect_err("invalid assembly should fail");
        assert!(error.to_string().contains("assembly failed"));
    }
}
