use super::*;

pub(crate) fn arithmetic_flag_effects(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
) -> Vec<SemanticEffect> {
    let bits = result.bits();
    let sign_left = sign_bit(left.clone());
    let sign_right = sign_bit(right.clone());
    let sign_result = sign_bit(result.clone());

    let carry = match op {
        SemanticOperationBinary::Add => {
            compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
        }
        SemanticOperationBinary::Sub => {
            compare(SemanticOperationCompare::Uge, left.clone(), right.clone())
        }
        _ => bool_const(false),
    };

    let overflow = match op {
        SemanticOperationBinary::Add => binary(
            SemanticOperationBinary::And,
            unary_not(binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            )),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        SemanticOperationBinary::Sub => binary(
            SemanticOperationBinary::And,
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            ),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        _ => bool_const(false),
    };

    vec![
        set_flag("n", sign_result),
        set_flag(
            "z",
            compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
        ),
        set_flag("c", carry),
        set_flag("v", overflow),
    ]
}

pub(crate) fn arithmetic_flag_values(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
) -> [SemanticExpression; 4] {
    let bits = result.bits();
    let sign_left = sign_bit(left.clone());
    let sign_right = sign_bit(right.clone());
    let sign_result = sign_bit(result.clone());

    let carry = match op {
        SemanticOperationBinary::Add => {
            compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
        }
        SemanticOperationBinary::Sub => {
            compare(SemanticOperationCompare::Uge, left.clone(), right.clone())
        }
        _ => bool_const(false),
    };

    let overflow = match op {
        SemanticOperationBinary::Add => binary(
            SemanticOperationBinary::And,
            unary_not(binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            )),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        SemanticOperationBinary::Sub => binary(
            SemanticOperationBinary::And,
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            ),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        _ => bool_const(false),
    };

    [
        sign_result,
        compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
        carry,
        overflow,
    ]
}

pub(crate) fn fp_compare_flag_values(
    left: SemanticExpression,
    right: SemanticExpression,
) -> [SemanticExpression; 4] {
    let unordered = compare(
        SemanticOperationCompare::Unordered,
        left.clone(),
        right.clone(),
    );
    [
        compare(SemanticOperationCompare::Olt, left.clone(), right.clone()),
        compare(SemanticOperationCompare::Oeq, left.clone(), right.clone()),
        binary(
            SemanticOperationBinary::Or,
            compare(SemanticOperationCompare::Oge, left.clone(), right.clone()),
            unordered.clone(),
            1,
        ),
        unordered,
    ]
}

pub(crate) fn condition_from_suffix(suffix: &str) -> Option<SemanticExpression> {
    let z = flag_expr("z");
    let n = flag_expr("n");
    let c = flag_expr("c");
    let v = flag_expr("v");

    Some(match suffix {
        "eq" => z,
        "ne" => unary_not(z),
        "hs" | "cs" => c,
        "lo" | "cc" => unary_not(c),
        "mi" => n,
        "pl" => unary_not(n),
        "vs" => v,
        "vc" => unary_not(v),
        "hi" => binary(
            SemanticOperationBinary::And,
            c,
            unary_not(flag_expr("z")),
            1,
        ),
        "ls" => binary(SemanticOperationBinary::Or, unary_not(c), flag_expr("z"), 1),
        "ge" => compare(SemanticOperationCompare::Eq, n, v),
        "lt" => compare(SemanticOperationCompare::Ne, n, v),
        "gt" => binary(
            SemanticOperationBinary::And,
            unary_not(flag_expr("z")),
            compare(SemanticOperationCompare::Eq, flag_expr("n"), flag_expr("v")),
            1,
        ),
        "le" => binary(
            SemanticOperationBinary::Or,
            flag_expr("z"),
            compare(SemanticOperationCompare::Ne, flag_expr("n"), flag_expr("v")),
            1,
        ),
        "al" | "nv" => bool_const(true),
        _ => return None,
    })
}

pub(crate) fn condition_from_cc(cc: u64) -> Option<SemanticExpression> {
    let suffix = match cc {
        1 => "eq",
        2 => "ne",
        3 => "hs",
        4 => "lo",
        5 => "mi",
        6 => "pl",
        7 => "vs",
        8 => "vc",
        9 => "hi",
        10 => "ls",
        11 => "ge",
        12 => "lt",
        13 => "gt",
        14 => "le",
        15 | 16 => "al",
        _ => return None,
    };
    condition_from_suffix(suffix)
}
