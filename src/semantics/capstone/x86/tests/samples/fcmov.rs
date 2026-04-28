use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "fcmovb",
        instruction: "fcmovb st(0), st(1)",
        architecture: Architecture::AMD64,
        bytes: &[0xda, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fcmove",
        instruction: "fcmove st(0), st(1)",
        architecture: Architecture::AMD64,
        bytes: &[0xda, 0xc9],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fcmovbe",
        instruction: "fcmovbe st(0), st(1)",
        architecture: Architecture::AMD64,
        bytes: &[0xda, 0xd1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fcmovnb",
        instruction: "fcmovnb st(0), st(1)",
        architecture: Architecture::AMD64,
        bytes: &[0xdb, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fcmovnbe",
        instruction: "fcmovnbe st(0), st(1)",
        architecture: Architecture::AMD64,
        bytes: &[0xdb, 0xd1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fcmovne",
        instruction: "fcmovne st(0), st(1)",
        architecture: Architecture::AMD64,
        bytes: &[0xdb, 0xc9],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fcmovu",
        instruction: "fcmovu st(0), st(1)",
        architecture: Architecture::AMD64,
        bytes: &[0xda, 0xd9],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "fcmovnu",
        instruction: "fcmovnu st(0), st(1)",
        architecture: Architecture::AMD64,
        bytes: &[0xdb, 0xd9],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
];

#[test]
fn fcmov_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
