use clap::ValueEnum;

#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum OperatingSystem {
    Linux,
    Macos,
    Windows,
}

impl OperatingSystem {
    pub const LINUX: Self = Self::Linux;
    pub const MACOS: Self = Self::Macos;
    pub const WINDOWS: Self = Self::Windows;

    pub const fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            return Self::Linux;
        }

        #[cfg(target_os = "macos")]
        {
            return Self::Macos;
        }

        #[cfg(target_os = "windows")]
        {
            return Self::Windows;
        }

        #[allow(unreachable_code)]
        Self::Linux
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash, ValueEnum,
)]
pub enum Transport {
    Inline,
    Ipc,
    Http,
}

impl Transport {
    pub const INLINE: Self = Self::Inline;
    pub const IPC: Self = Self::Ipc;
    pub const HTTP: Self = Self::Http;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Ipc => "ipc",
            Self::Http => "http",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "inline" => Some(Self::Inline),
            "ipc" => Some(Self::Ipc),
            "http" => Some(Self::Http),
            _ => None,
        }
    }

    pub const fn is_inline(self) -> bool {
        matches!(self, Self::Inline)
    }

    pub const fn is_local(self) -> bool {
        self.is_inline()
    }
}
