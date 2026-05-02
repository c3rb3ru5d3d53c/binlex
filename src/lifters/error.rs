use super::LifterBackend;
use crate::Architecture;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifterCapability {
    LiftSemantics,
    Bitcode,
    Embedding,
    Object,
    Verify,
    Optimizers,
    Mem2Reg,
    InstCombine,
    Cfg,
    Gvn,
    Sroa,
    Dce,
}

impl Display for LifterCapability {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::LiftSemantics => "lift_semantics",
            Self::Bitcode => "bitcode",
            Self::Embedding => "embedding",
            Self::Object => "object",
            Self::Verify => "verify",
            Self::Optimizers => "optimizers",
            Self::Mem2Reg => "mem2reg",
            Self::InstCombine => "instcombine",
            Self::Cfg => "cfg",
            Self::Gvn => "gvn",
            Self::Sroa => "sroa",
            Self::Dce => "dce",
        };
        write!(f, "{name}")
    }
}

#[derive(Debug)]
pub enum LifterError {
    UnsupportedBackend {
        backend: LifterBackend,
        architecture: Architecture,
    },
    UnsupportedCapability {
        backend: LifterBackend,
        capability: LifterCapability,
    },
    Io(std::io::Error),
}

impl Display for LifterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedBackend {
                backend,
                architecture,
            } => {
                write!(
                    f,
                    "lifter backend {backend} is unsupported for architecture {architecture}"
                )
            }
            Self::UnsupportedCapability {
                backend,
                capability,
            } => {
                write!(
                    f,
                    "lifter backend {backend} does not support capability {capability}"
                )
            }
            Self::Io(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for LifterError {}

impl From<std::io::Error> for LifterError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
