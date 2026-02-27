use libvex::{Arch, VexEndness};

pub struct VexLifter {
    pub guest_arch: Arch,
    pub host_arch: Arch,
    pub endness: VexEndness,
}

impl VexLifter {
    pub fn new() -> Self {
        let host_arch = if cfg!(target_arch = "aarch64") {
            Arch::VexArchARM64
        } else {
            Arch::VexArchAMD64
        };
        VexLifter {
            guest_arch: Arch::VexArchAMD64,
            host_arch,
            endness: VexEndness::VexEndnessLE,
        }
    }
}
