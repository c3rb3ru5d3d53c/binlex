use std::env;
use std::io::ErrorKind;
use std::path::Path;

use interprocess::local_socket::{
    GenericFilePath, GenericNamespaced, Listener, ListenerOptions, Stream, prelude::*,
};
use rand::{RngCore, SeedableRng, rngs::SmallRng};

use crate::runtime::error::ProcessorError;

pub fn bind_listener(prefix: &str) -> Result<(String, Listener), ProcessorError> {
    let primary = generated_name(prefix);
    match listener_for_name(&primary) {
        Ok(listener) => Ok((primary, listener)),
        Err(ProcessorError::Io(error))
            if !Path::new(&primary).is_absolute()
                && matches!(
                    error.kind(),
                    ErrorKind::PermissionDenied | ErrorKind::AddrNotAvailable | ErrorKind::Other
                ) =>
        {
            let fallback = generated_filesystem_name(prefix);
            let listener = listener_for_name(&fallback)?;
            Ok((fallback, listener))
        }
        Err(error) => Err(error),
    }
}

pub fn connect(name: &str) -> Result<Stream, ProcessorError> {
    if Path::new(name).is_absolute() {
        Ok(Stream::connect(name.to_fs_name::<GenericFilePath>()?)?)
    } else {
        Ok(Stream::connect(name.to_ns_name::<GenericNamespaced>()?)?)
    }
}

fn listener_for_name(name: &str) -> Result<Listener, ProcessorError> {
    if Path::new(name).is_absolute() {
        Ok(ListenerOptions::new()
            .name(name.to_fs_name::<GenericFilePath>()?)
            .reclaim_name(true)
            .create_sync()?)
    } else {
        Ok(ListenerOptions::new()
            .name(name.to_ns_name::<GenericNamespaced>()?)
            .create_sync()?)
    }
}

fn generated_name(prefix: &str) -> String {
    let mut rng = SmallRng::from_entropy();
    let suffix = rng.next_u64();
    if GenericNamespaced::is_supported() {
        format!("{}-{}-{}", prefix, std::process::id(), suffix)
    } else {
        generated_filesystem_name_with_suffix(prefix, suffix)
    }
}

fn generated_filesystem_name(prefix: &str) -> String {
    let mut rng = SmallRng::from_entropy();
    generated_filesystem_name_with_suffix(prefix, rng.next_u64())
}

fn generated_filesystem_name_with_suffix(prefix: &str, suffix: u64) -> String {
    env::temp_dir()
        .join(format!("{}-{}-{}.sock", prefix, std::process::id(), suffix))
        .to_string_lossy()
        .into_owned()
}
