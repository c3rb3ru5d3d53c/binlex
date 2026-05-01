use crate::semantics::{SemanticExpression, SemanticLocation};
use crate::symbolic::{Error, Executor, State};
use z3::ast::{Ast, BV, Bool, RoundingMode};

impl Executor {
    pub(crate) fn eval_x87_intrinsic_expression(
        &self,
        state: &mut State,
        name: &str,
        args: &[SemanticExpression],
        bits: u16,
    ) -> Result<Option<BV>, Error> {
        if let Some(constant) = name.strip_prefix("x86.x87.const_") {
            return Ok(Some(self.eval_x87_constant(state, constant, bits)?));
        }
        if !name.starts_with("x86.x87.") {
            return Ok(None);
        }

        let op = &name["x86.x87.".len()..];
        let evaluated = args
            .iter()
            .map(|arg| self.eval_expression(state, arg, true))
            .collect::<Result<Vec<_>, _>>()?;

        let value = match op {
            "add" | "sub" | "mul" | "div" => {
                let [left, right] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let left = state.backend().float_from_ieee_bv(&left.value)?;
                let right = state.backend().float_from_ieee_bv(&right.value)?;
                let rounding = RoundingMode::round_nearest_ties_to_even();
                let result = match op {
                    "add" => left.add_with_rounding_mode(&right, &rounding),
                    "sub" => left.sub_with_rounding_mode(&right, &rounding),
                    "mul" => left.mul_with_rounding_mode(&right, &rounding),
                    "div" => left.div_with_rounding_mode(&right, &rounding),
                    _ => unreachable!(),
                };
                state.backend().float_to_ieee_bv(&result)
            }
            "abs" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                self.eval_fp_abs(state, value.value.clone())?
            }
            "neg" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                self.eval_fp_neg(state, value.value.clone())?
            }
            "sqrt" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                self.eval_fp_sqrt(state, value.value.clone())?
            }
            "rint" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(&value.value)?;
                let rounded = value.round_to_integral_with_rounding_mode(
                    &RoundingMode::round_nearest_ties_to_even(),
                );
                state.backend().float_to_ieee_bv(&rounded)
            }
            "load_f32" | "load_f64" => {
                let [raw] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(&raw.value)?;
                let value = state.backend().float_cast(&value, bits)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "load_i16" | "load_i32" | "load_i64" => {
                let [raw] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().signed_bv_to_float(&raw.value, bits)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "load_bcd" => {
                let [raw] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let raw = self
                    .concrete_bv_u128(&raw.value)
                    .ok_or(Error::UnsupportedExpression(
                        "x87 intrinsic requires concrete value",
                    ))?;
                let integer = self.decode_x87_bcd(raw)?;
                let integer = state.backend().const_bv(integer as u128, 64)?;
                let value = state.backend().signed_bv_to_float(&integer, bits)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "store_f32" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(&value.value)?;
                let value = state.backend().float_cast(&value, 32)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "store_f64" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = state.backend().float_from_ieee_bv(&value.value)?;
                let value = state.backend().float_cast(&value, 64)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "store_bcd" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let value = self.try_concrete_f64_from_fp_bv(state, &value.value).ok_or(
                    Error::UnsupportedExpression("x87 intrinsic requires concrete value"),
                )?;
                if !value.is_finite() || value < i64::MIN as f64 || value > i64::MAX as f64 {
                    return Err(Error::UnsupportedExpression("x87 bcd value out of range"));
                }
                let rounded = value.round_ties_even() as i64;
                state
                    .backend()
                    .const_bv(self.encode_x87_bcd(rounded), bits)?
            }
            "sin" | "cos" | "tan" | "f2xm1" => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let concrete = self.try_concrete_f64_from_fp_bv(state, &value.value).ok_or(
                    Error::UnsupportedExpression("x87 intrinsic requires concrete value"),
                )?;
                let result = match op {
                    "sin" => concrete.sin(),
                    "cos" => concrete.cos(),
                    "tan" => concrete.tan(),
                    "f2xm1" => 2.0f64.powf(concrete) - 1.0,
                    _ => unreachable!(),
                };
                let value = state.backend().float_from_f64(bits, result)?;
                state.backend().float_to_ieee_bv(&value)
            }
            "atan2" | "yl2x" | "yl2xp1" | "scale" => {
                let [left, right] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let left = self.try_concrete_f64_from_fp_bv(state, &left.value).ok_or(
                    Error::UnsupportedExpression("x87 intrinsic requires concrete value"),
                )?;
                let right = self.try_concrete_f64_from_fp_bv(state, &right.value).ok_or(
                    Error::UnsupportedExpression("x87 intrinsic requires concrete value"),
                )?;
                let result = match op {
                    "atan2" => left.atan2(right),
                    "yl2x" => left * right.log2(),
                    "yl2xp1" => left * (right + 1.0).log2(),
                    "scale" => left * 2.0f64.powf(right.trunc()),
                    _ => unreachable!(),
                };
                let value = state.backend().float_from_f64(bits, result)?;
                state.backend().float_to_ieee_bv(&value)
            }
            op if op.starts_with("store_i") => {
                let [value] = evaluated.as_slice() else {
                    return Err(Error::UnsupportedExpression("x87 intrinsic arity"));
                };
                let (target_bits, trunc) = self.parse_x87_store_int_op(op)?;
                let value = state.backend().float_from_ieee_bv(&value.value)?;
                let rounded = if trunc {
                    value.to_sbv_with_rounding_mode(
                        &RoundingMode::round_towards_zero(),
                        target_bits as u32,
                    )
                } else {
                    value.to_sbv_with_rounding_mode(
                        &RoundingMode::round_nearest_ties_to_even(),
                        target_bits as u32,
                    )
                };
                rounded.zero_ext((bits - target_bits) as u32)
            }
            _ => return Ok(None),
        };

        Ok(Some(state.backend().coerce_bv_width(&value, bits)?))
    }

    fn eval_x87_constant(&self, state: &State, name: &str, bits: u16) -> Result<BV, Error> {
        let value = match name {
            "one" => 1.0,
            "zero" => 0.0,
            "pi" => std::f64::consts::PI,
            "l2t" => std::f64::consts::LOG2_10,
            "l2e" => std::f64::consts::LOG2_E,
            "lg2" => std::f64::consts::LOG10_2,
            "ln2" => std::f64::consts::LN_2,
            _ => return Err(Error::UnsupportedExpression("x87 constant")),
        };
        let value = state.backend().float_from_f64(bits, value)?;
        Ok(state.backend().float_to_ieee_bv(&value))
    }

    fn try_concrete_f64_from_fp_bv(&self, state: &State, value: &BV) -> Option<f64> {
        let value = state.backend().float_from_ieee_bv(value).ok()?;
        let value = state.backend().float_cast(&value, 64).ok()?;
        let bits = state.backend().float_to_ieee_bv(&value).simplify();
        bits.as_u64().map(f64::from_bits)
    }

    fn encode_x87_bcd(&self, value: i64) -> u128 {
        let negative = value.is_negative();
        let mut magnitude = value.unsigned_abs();
        let mut bytes = [0u8; 10];
        for byte in bytes.iter_mut().take(9) {
            let low = (magnitude % 10) as u8;
            magnitude /= 10;
            let high = (magnitude % 10) as u8;
            magnitude /= 10;
            *byte = low | (high << 4);
        }
        let top_digit = (magnitude % 10) as u8;
        bytes[9] = top_digit | if negative { 0x80 } else { 0x00 };
        u128::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], 0, 0, 0, 0, 0, 0,
        ])
    }

    fn decode_x87_bcd(&self, raw: u128) -> Result<i64, Error> {
        let bytes = raw.to_le_bytes();
        let mut digits = 0u64;
        let mut factor = 1u64;
        for byte in bytes.iter().take(9) {
            let low = byte & 0x0f;
            let high = (byte >> 4) & 0x0f;
            if low > 9 || high > 9 {
                return Err(Error::UnsupportedExpression("invalid x87 bcd digit"));
            }
            digits = digits
                .checked_add((low as u64).saturating_mul(factor))
                .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
            factor = factor
                .checked_mul(10)
                .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
            digits = digits
                .checked_add((high as u64).saturating_mul(factor))
                .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
            factor = factor
                .checked_mul(10)
                .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
        }
        let top = bytes[9] & 0x0f;
        if top > 9 {
            return Err(Error::UnsupportedExpression("invalid x87 bcd digit"));
        }
        digits = digits
            .checked_add((top as u64).saturating_mul(factor))
            .ok_or(Error::UnsupportedExpression("x87 bcd overflow"))?;
        let negative = (bytes[9] & 0x80) != 0;
        if negative {
            Ok(-(digits as i64))
        } else {
            Ok(digits as i64)
        }
    }

    pub(crate) fn apply_intrinsic_effect(
        &self,
        state: &mut State,
        instruction: Option<&crate::semantics::InstructionEncoding>,
        name: &str,
        args: &[SemanticExpression],
        outputs: &[SemanticLocation],
    ) -> Result<(), Error> {
        if name == "x86.x87.xam" {
            return self.apply_x87_xam_effect(state, instruction, args, outputs);
        }
        Err(Error::UnsupportedEffect("intrinsic"))
    }

    fn apply_x87_xam_effect(
        &self,
        state: &mut State,
        instruction: Option<&crate::semantics::InstructionEncoding>,
        args: &[SemanticExpression],
        outputs: &[SemanticLocation],
    ) -> Result<(), Error> {
        let [arg] = args else {
            return Err(Error::UnsupportedEffect("x87 xam arity"));
        };
        if outputs.len() != 4 {
            return Err(Error::UnsupportedEffect("x87 xam outputs"));
        }

        let evaluated = self.eval_expression(state, arg, true)?;
        let value = state.backend().float_from_ieee_bv(&evaluated.value)?;

        let c0 = Bool::or(&[value.is_nan(), value.is_infinite()]);
        let c1 = value.is_negative();
        let c2 = Bool::or(&[value.is_normal(), value.is_infinite(), value.is_subnormal()]);
        let c3 = Bool::or(&[value.is_zero(), value.is_subnormal()]);

        let flags = [c0, c1, c2, c3];
        for (output, flag) in outputs.iter().zip(flags.into_iter()) {
            let bits = output.bits();
            let value = crate::symbolic::expressions::EvaluatedValue {
                value: state.backend().bool_to_bv(&flag, bits)?,
                deps: evaluated.deps.clone(),
            };
            self.write_location(state, instruction, output, value)?;
        }
        Ok(())
    }

    fn parse_x87_store_int_op(&self, op: &str) -> Result<(u16, bool), Error> {
        let Some(suffix) = op.strip_prefix("store_i") else {
            return Err(Error::UnsupportedExpression("x87 store intrinsic"));
        };
        let trunc = suffix.ends_with("_trunc");
        let width = if trunc {
            &suffix[..suffix.len() - "_trunc".len()]
        } else {
            suffix
        };
        let bits = width
            .parse::<u16>()
            .map_err(|_| Error::UnsupportedExpression("x87 store intrinsic"))?;
        match bits {
            16 | 32 | 64 => Ok((bits, trunc)),
            _ => Err(Error::UnsupportedExpression("x87 store intrinsic")),
        }
    }
}
