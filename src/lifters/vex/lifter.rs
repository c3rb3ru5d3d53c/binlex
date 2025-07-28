use libvex::{Arch, VexEndness};

pub struct VexLifter {
    pub arch: Arch,
    pub endness: VexEndness,
}

impl VexLifter {
    pub fn new() -> Self {
        VexLifter {
            arch: Arch::VexArchAMD64,
            endness: VexEndness::VexEndnessLE,
        }
    }
} 