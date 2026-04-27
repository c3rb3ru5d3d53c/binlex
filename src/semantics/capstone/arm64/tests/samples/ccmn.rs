use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, eq",
        bytes: &[0x00, 0x00, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, eq",
        bytes: &[0x00, 0x00, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, eq",
        bytes: &[0x00, 0x08, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, eq",
        bytes: &[0x00, 0x00, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, eq",
        bytes: &[0x00, 0x08, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("z", 1), ("n", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, eq",
        bytes: &[0x0a, 0x00, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, eq",
        bytes: &[0x0a, 0x08, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, eq",
        bytes: &[0x0a, 0x00, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, eq",
        bytes: &[0x0a, 0x08, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("z", 0), ("n", 0), ("c", 0), ("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, gt",
        bytes: &[0x00, 0xc0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, gt",
        bytes: &[0x00, 0xc8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, gt",
        bytes: &[0x00, 0xc0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, gt",
        bytes: &[0x00, 0xc8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, gt",
        bytes: &[0x0a, 0xc0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, gt",
        bytes: &[0x0a, 0xc8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, gt",
        bytes: &[0x0a, 0xc0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, gt",
        bytes: &[0x0a, 0xc8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, hi",
        bytes: &[0x00, 0x80, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, hi",
        bytes: &[0x00, 0x88, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, hi",
        bytes: &[0x00, 0x80, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, hi",
        bytes: &[0x00, 0x88, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, hi",
        bytes: &[0x0a, 0x80, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, hi",
        bytes: &[0x0a, 0x88, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, hi",
        bytes: &[0x0a, 0x80, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, hi",
        bytes: &[0x0a, 0x88, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, vs",
        bytes: &[0x00, 0x60, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, vs",
        bytes: &[0x00, 0x68, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, vs",
        bytes: &[0x00, 0x60, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, vs",
        bytes: &[0x00, 0x68, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, vs",
        bytes: &[0x0a, 0x60, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, vs",
        bytes: &[0x0a, 0x68, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, vs",
        bytes: &[0x0a, 0x60, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, vs",
        bytes: &[0x0a, 0x68, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, ge",
        bytes: &[0x00, 0xa0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 1), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, ge",
        bytes: &[0x00, 0xa8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 1), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, ge",
        bytes: &[0x00, 0xa0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 1), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, ge",
        bytes: &[0x00, 0xa8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 1), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, ge",
        bytes: &[0x0a, 0xa0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 1), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, ge",
        bytes: &[0x0a, 0xa8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 1), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, ge",
        bytes: &[0x0a, 0xa0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 1), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, ge",
        bytes: &[0x0a, 0xa8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 1), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, lt",
        bytes: &[0x00, 0xb0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 1), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, lt",
        bytes: &[0x00, 0xb8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 1), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, lt",
        bytes: &[0x00, 0xb0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 1), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, lt",
        bytes: &[0x00, 0xb8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 1), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, lt",
        bytes: &[0x0a, 0xb0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 0), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, lt",
        bytes: &[0x0a, 0xb8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 0), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, lt",
        bytes: &[0x0a, 0xb0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 0), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, lt",
        bytes: &[0x0a, 0xb8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 0), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, le",
        bytes: &[0x00, 0xd0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, le",
        bytes: &[0x00, 0xd8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, le",
        bytes: &[0x00, 0xd0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, le",
        bytes: &[0x00, 0xd8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, le",
        bytes: &[0x0a, 0xd0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, le",
        bytes: &[0x0a, 0xd8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, le",
        bytes: &[0x0a, 0xd0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, le",
        bytes: &[0x0a, 0xd8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, hs",
        bytes: &[0x00, 0x20, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, hs",
        bytes: &[0x00, 0x28, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, hs",
        bytes: &[0x00, 0x20, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, hs",
        bytes: &[0x00, 0x28, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, hs",
        bytes: &[0x0a, 0x20, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, hs",
        bytes: &[0x0a, 0x28, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, hs",
        bytes: &[0x0a, 0x20, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, hs",
        bytes: &[0x0a, 0x28, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, lo",
        bytes: &[0x00, 0x30, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, lo",
        bytes: &[0x00, 0x38, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, lo",
        bytes: &[0x00, 0x30, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, lo",
        bytes: &[0x00, 0x38, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, lo",
        bytes: &[0x0a, 0x30, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, lo",
        bytes: &[0x0a, 0x38, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, lo",
        bytes: &[0x0a, 0x30, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, lo",
        bytes: &[0x0a, 0x38, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, vc",
        bytes: &[0x00, 0x70, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, vc",
        bytes: &[0x00, 0x78, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, vc",
        bytes: &[0x00, 0x70, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, vc",
        bytes: &[0x00, 0x78, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("v", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, vc",
        bytes: &[0x0a, 0x70, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, vc",
        bytes: &[0x0a, 0x78, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, vc",
        bytes: &[0x0a, 0x70, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, vc",
        bytes: &[0x0a, 0x78, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("v", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, mi",
        bytes: &[0x00, 0x40, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, mi",
        bytes: &[0x00, 0x48, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, mi",
        bytes: &[0x00, 0x40, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, mi",
        bytes: &[0x00, 0x48, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, mi",
        bytes: &[0x0a, 0x40, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, mi",
        bytes: &[0x0a, 0x48, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, mi",
        bytes: &[0x0a, 0x40, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, mi",
        bytes: &[0x0a, 0x48, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, pl",
        bytes: &[0x00, 0x50, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, pl",
        bytes: &[0x00, 0x58, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, pl",
        bytes: &[0x00, 0x50, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, pl",
        bytes: &[0x00, 0x58, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, pl",
        bytes: &[0x0a, 0x50, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, pl",
        bytes: &[0x0a, 0x58, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, pl",
        bytes: &[0x0a, 0x50, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, pl",
        bytes: &[0x0a, 0x58, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, al",
        bytes: &[0x00, 0xe0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, al",
        bytes: &[0x00, 0xe8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, al",
        bytes: &[0x00, 0xe0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, al",
        bytes: &[0x00, 0xe8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, ls",
        bytes: &[0x00, 0x90, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, ls",
        bytes: &[0x00, 0x98, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, ls",
        bytes: &[0x00, 0x90, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, ls",
        bytes: &[0x00, 0x98, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, ls",
        bytes: &[0x0a, 0x90, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, ls",
        bytes: &[0x0a, 0x98, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, ls",
        bytes: &[0x0a, 0x90, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, ls",
        bytes: &[0x0a, 0x98, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, ne",
        bytes: &[0x00, 0x10, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, ne",
        bytes: &[0x00, 0x18, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, ne",
        bytes: &[0x00, 0x10, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, ne",
        bytes: &[0x00, 0x18, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, ne",
        bytes: &[0x0a, 0x10, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, ne",
        bytes: &[0x0a, 0x18, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, ne",
        bytes: &[0x0a, 0x10, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, ne",
        bytes: &[0x0a, 0x18, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #0, nv",
        bytes: &[0x00, 0xf0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #0, nv",
        bytes: &[0x00, 0xf8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #0, nv",
        bytes: &[0x00, 0xf0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #0, nv",
        bytes: &[0x00, 0xf8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, x1, #10, nv",
        bytes: &[0x0a, 0xf0, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	x0, #1, #10, nv",
        bytes: &[0x0a, 0xf8, 0x41, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, w1, #10, nv",
        bytes: &[0x0a, 0xf0, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 3), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ccmn",
        instruction: "ccmn	w0, #1, #10, nv",
        bytes: &[0x0a, 0xf8, 0x41, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn ccmn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ccmn_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
