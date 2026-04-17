use inkwell::module::Module;
use std::io::Error;

pub fn verify_module(module: &Module<'_>) -> Result<(), Error> {
    module.verify().map_err(|err| Error::other(err.to_string()))
}
