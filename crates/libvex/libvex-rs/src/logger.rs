use std::cell::RefCell;
use std::io::{self, Write};
use std::mem;
use std::str::Utf8Error;

use lazy_static::lazy_static;
use parking_lot::ReentrantMutex;

pub struct VexLogger(Option<Vec<u8>>);

impl Write for VexLogger {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            Some(vec) => Write::write(vec, buf),
            None => Write::write(&mut io::stderr(), buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut io::stderr())
    }
}

impl VexLogger {
    fn new() -> ReentrantMutex<RefCell<Self>> {
        ReentrantMutex::new(RefCell::new(Self(None)))
    }
}

lazy_static! {
    pub static ref VEX_LOG: ReentrantMutex<RefCell<VexLogger>> = VexLogger::new();
}

pub fn with<F, R>(mut f: F) -> (R, Result<String, Utf8Error>)
where
    F: FnMut() -> R,
{
    let guard = VEX_LOG.lock();
    let old = guard.borrow_mut().0.replace(Vec::new());
    let res = f();
    let s = mem::replace(&mut guard.borrow_mut().0, old).unwrap();
    (res, std::str::from_utf8(&s).map(str::to_string))
}
