use crate::lifters::llvm::Lifter;
use std::io::Error;

pub struct Optimizers {
    lifter: Lifter,
}

impl Optimizers {
    pub(crate) fn new(lifter: Lifter) -> Self {
        Self { lifter }
    }

    pub fn mem2reg(self) -> Result<Self, Error> {
        Ok(Self::new(self.lifter.mem2reg()?))
    }

    pub fn instcombine(self) -> Result<Self, Error> {
        Ok(Self::new(self.lifter.instcombine()?))
    }

    pub fn cfg(self) -> Result<Self, Error> {
        Ok(Self::new(self.lifter.cfg()?))
    }

    pub fn gvn(self) -> Result<Self, Error> {
        Ok(Self::new(self.lifter.gvn()?))
    }

    pub fn sroa(self) -> Result<Self, Error> {
        Ok(Self::new(self.lifter.sroa()?))
    }

    pub fn dce(self) -> Result<Self, Error> {
        Ok(Self::new(self.lifter.dce()?))
    }

    pub fn text(&self) -> String {
        self.lifter.text()
    }

    pub fn bitcode(&self) -> Vec<u8> {
        self.lifter.bitcode()
    }

    pub fn normalized(&self) -> Result<Lifter, Error> {
        self.lifter.normalized()
    }

    pub fn verify(&self) -> Result<(), Error> {
        self.lifter.verify()
    }

    pub fn into_lifter(self) -> Lifter {
        self.lifter
    }
}
