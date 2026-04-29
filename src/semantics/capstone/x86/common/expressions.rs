use super::*;

pub fn bool_const(value: bool) -> SemanticExpression {
    const_u64(value as u64, 1)
}

pub fn add(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Add,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn mul(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn sub(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Sub,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn xor(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Xor,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn and(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::And,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn or(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Or,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn compare(
    op: SemanticOperationCompare,
    left: SemanticExpression,
    right: SemanticExpression,
) -> SemanticExpression {
    SemanticExpression::Compare {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits: 1,
    }
}

pub fn extract_bit(arg: SemanticExpression, lsb: u16) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(arg),
        lsb,
        bits: 1,
    }
}

pub fn extract_low_byte(arg: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(arg),
        lsb: 0,
        bits: 8,
    }
}

pub fn not(arg: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(arg),
        bits,
    }
}

pub fn parity_flag(arg: SemanticExpression) -> SemanticExpression {
    let low_byte = extract_low_byte(arg);
    let pop_count = SemanticExpression::Unary {
        op: SemanticOperationUnary::PopCount,
        arg: Box::new(low_byte),
        bits: 8,
    };
    compare(
        SemanticOperationCompare::Eq,
        extract_bit(pop_count, 0),
        bool_const(false),
    )
}

pub fn auxiliary_flag(
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    extract_bit(xor(xor(left, right, bits), result, bits), 4)
}

pub fn add_overflow(
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    extract_bit(
        and(
            not(xor(left.clone(), right, bits), bits),
            xor(left, result, bits),
            bits,
        ),
        bits - 1,
    )
}

pub fn sub_overflow(
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    extract_bit(
        and(
            xor(left.clone(), right, bits),
            xor(left, result, bits),
            bits,
        ),
        bits - 1,
    )
}

pub fn operation_intrinsic(
    instruction: &Insn,
    bits: u16,
    args: Vec<SemanticExpression>,
) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: format!("x86.{}", instruction.mnemonic().unwrap_or("unknown")),
        args,
        bits,
    }
}
