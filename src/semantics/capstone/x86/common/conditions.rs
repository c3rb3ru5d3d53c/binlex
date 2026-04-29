use super::*;

pub fn condition_intrinsic(instruction: &Insn) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: format!(
            "x86.condition.{}",
            instruction.mnemonic().unwrap_or("unknown")
        ),
        args: Vec::new(),
        bits: 1,
    }
}

fn condition_suffix(mnemonic: &str) -> Option<&str> {
    if let Some(suffix) = mnemonic.strip_prefix("cmov") {
        return Some(suffix);
    }
    if let Some(suffix) = mnemonic.strip_prefix("set") {
        return Some(suffix);
    }
    if let Some(suffix) = mnemonic.strip_prefix('j') {
        return Some(suffix);
    }
    None
}

pub fn condition_from_mnemonic(mnemonic: &str) -> Option<SemanticExpression> {
    let suffix = condition_suffix(mnemonic)?;
    let zf = flag_expr("zf");
    let cf = flag_expr("cf");
    let sf = flag_expr("sf");
    let of = flag_expr("of");
    let pf = flag_expr("pf");

    match suffix {
        "e" | "z" => Some(zf),
        "ne" | "nz" => Some(compare(SemanticOperationCompare::Eq, zf, bool_const(false))),
        "b" | "c" | "nae" => Some(cf),
        "ae" | "nb" | "nc" => Some(compare(SemanticOperationCompare::Eq, cf, bool_const(false))),
        "be" | "na" => Some(or(zf, cf, 1)),
        "a" | "nbe" => {
            let not_cf = compare(SemanticOperationCompare::Eq, cf, bool_const(false));
            let not_zf = compare(SemanticOperationCompare::Eq, zf, bool_const(false));
            Some(and(not_cf, not_zf, 1))
        }
        "s" => Some(sf),
        "ns" => Some(compare(SemanticOperationCompare::Eq, sf, bool_const(false))),
        "o" => Some(of),
        "no" => Some(compare(SemanticOperationCompare::Eq, of, bool_const(false))),
        "p" | "pe" => Some(pf),
        "np" | "po" => Some(compare(SemanticOperationCompare::Eq, pf, bool_const(false))),
        "l" | "nge" => Some(xor(sf, of, 1)),
        "ge" | "nl" => Some(compare(
            SemanticOperationCompare::Eq,
            xor(sf, of, 1),
            bool_const(false),
        )),
        "le" | "ng" => Some(or(zf, xor(sf, of, 1), 1)),
        "g" | "nle" => {
            let not_zf = compare(SemanticOperationCompare::Eq, zf, bool_const(false));
            let sf_eq_of = compare(
                SemanticOperationCompare::Eq,
                xor(sf, of, 1),
                bool_const(false),
            );
            Some(and(not_zf, sf_eq_of, 1))
        }
        _ => None,
    }
}
