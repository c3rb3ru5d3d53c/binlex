use crate::irs::lir::executor::LirExecutorError;
use std::collections::HashMap;
use z3::ast::{Array, Ast, BV, Bool, Float, RoundingMode};
use z3::{Context, Model, SatResult, Solver, Sort};

#[derive(Clone)]
pub(crate) enum TrackedAst {
    BitVector(BV),
}

impl TrackedAst {
    pub(crate) fn eval_string(&self, model: &Model) -> Option<String> {
        match self {
            Self::BitVector(value) => model.eval(value, true).map(|evaluated| {
                evaluated
                    .as_u64()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| evaluated.to_string())
            }),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct Z3Backend;

impl Z3Backend {
    pub(crate) fn new() -> Self {
        let _ = Context::thread_local();
        Self
    }

    pub(crate) fn const_bv(&self, value: u128, bits: u16) -> Result<BV, LirExecutorError> {
        if bits == 0 {
            return Err(LirExecutorError::invalid_bits(0));
        }
        if bits <= 64 {
            Ok(BV::from_u64(value as u64, bits as u32))
        } else {
            BV::from_str(bits as u32, &value.to_string())
                .ok_or_else(|| LirExecutorError::solver("failed to build bitvector constant"))
        }
    }

    pub(crate) fn zero_bv(&self, bits: u16) -> Result<BV, LirExecutorError> {
        self.const_bv(0, bits)
    }

    pub(crate) fn one_bv(&self, bits: u16) -> Result<BV, LirExecutorError> {
        self.const_bv(1, bits)
    }

    pub(crate) fn fresh_bv(&self, name: &str, bits: u16) -> Result<BV, LirExecutorError> {
        if bits == 0 {
            return Err(LirExecutorError::invalid_bits(0));
        }
        Ok(BV::new_const(name, bits as u32))
    }

    pub(crate) fn bool_to_bv(&self, value: &Bool, bits: u16) -> Result<BV, LirExecutorError> {
        let one = self.one_bv(bits)?;
        let zero = self.zero_bv(bits)?;
        Ok(value.ite(&one, &zero))
    }

    pub(crate) fn bv_to_bool(&self, value: &BV) -> Bool {
        value.eq(0).not()
    }

    pub(crate) fn coerce_bv_width(&self, value: &BV, bits: u16) -> Result<BV, LirExecutorError> {
        let current = value.get_size() as u16;
        if current == bits {
            return Ok(value.clone());
        }
        if current < bits {
            return Ok(value.zero_ext((bits - current) as u32));
        }
        Ok(value.extract((bits - 1) as u32, 0))
    }

    pub(crate) fn solver_from_constraints(&self, constraints: &[Bool]) -> Solver {
        let solver = Solver::new();
        for constraint in constraints {
            solver.assert(constraint);
        }
        solver
    }

    pub(crate) fn is_sat(&self, constraints: &[Bool]) -> Result<bool, LirExecutorError> {
        Ok(matches!(
            self.solver_from_constraints(constraints).check(),
            SatResult::Sat
        ))
    }

    pub(crate) fn smt(&self, constraints: &[Bool]) -> String {
        let solver = self.solver_from_constraints(constraints);
        let mut script = solver.to_smt2();
        if !script.ends_with('\n') {
            script.push('\n');
        }
        if !script.contains("(check-sat)") {
            script.push_str("(check-sat)\n");
        }
        if !script.contains("(get-model)") {
            script.push_str("(get-model)\n");
        }
        script
    }

    pub(crate) fn model(
        &self,
        constraints: &[Bool],
        tracked: &HashMap<String, TrackedAst>,
    ) -> Result<HashMap<String, String>, LirExecutorError> {
        let solver = self.solver_from_constraints(constraints);
        match solver.check() {
            SatResult::Sat => {
                let model = solver.get_model().ok_or_else(|| {
                    LirExecutorError::solver("solver reported sat without a model")
                })?;
                let mut result = HashMap::new();
                for (name, value) in tracked {
                    if let Some(evaluated) = value.eval_string(&model) {
                        result.insert(name.clone(), evaluated);
                    }
                }
                Ok(result)
            }
            SatResult::Unsat => Err(LirExecutorError::Unsatisfiable),
            SatResult::Unknown => Err(LirExecutorError::solver("solver returned unknown")),
        }
    }

    pub(crate) fn eval_bv_u64(
        &self,
        constraints: &[Bool],
        value: &BV,
    ) -> Result<Option<u64>, LirExecutorError> {
        let solver = self.solver_from_constraints(constraints);
        match solver.check() {
            SatResult::Sat => {
                let model = solver.get_model().ok_or_else(|| {
                    LirExecutorError::solver("solver reported sat without a model")
                })?;
                Ok(model
                    .eval(value, true)
                    .and_then(|evaluated| evaluated.as_u64()))
            }
            SatResult::Unsat => Ok(None),
            SatResult::Unknown => Err(LirExecutorError::solver("solver returned unknown")),
        }
    }

    pub(crate) fn new_memory(&self, address_bits: u32) -> Array {
        Array::const_array(&Sort::bitvector(address_bits), &BV::from_u64(0, 8))
    }

    pub(crate) fn memory_select(
        &self,
        memory: &Array,
        address: &BV,
    ) -> Result<BV, LirExecutorError> {
        memory
            .select(address)
            .as_bv()
            .ok_or_else(|| LirExecutorError::solver("memory select did not return a bitvector"))
    }

    pub(crate) fn float_from_ieee_bv(&self, value: &BV) -> Result<Float, LirExecutorError> {
        let sort = self.float_sort(value.get_size() as u16)?;
        let ctx = value.get_ctx();
        let ast = unsafe {
            z3_sys::Z3_mk_fpa_to_fp_bv(ctx.get_z3_context(), value.get_z3_ast(), sort.get_z3_sort())
                .ok_or_else(|| {
                    LirExecutorError::solver("failed to reinterpret bitvector as float")
                })?
        };
        Ok(unsafe { <Float as Ast>::wrap(ctx, ast) })
    }

    pub(crate) fn float_to_ieee_bv(&self, value: &Float) -> BV {
        value.to_ieee_bv()
    }

    pub(crate) fn float_from_f64(&self, bits: u16, value: f64) -> Result<Float, LirExecutorError> {
        let sort = self.float_sort(bits)?;
        let ctx = Context::thread_local();
        let ast = unsafe {
            z3_sys::Z3_mk_fpa_numeral_double(ctx.get_z3_context(), value, sort.get_z3_sort())
                .ok_or_else(|| LirExecutorError::solver("failed to build floating-point numeral"))?
        };
        Ok(unsafe { <Float as Ast>::wrap(&ctx, ast) })
    }

    pub(crate) fn signed_bv_to_float(
        &self,
        value: &BV,
        bits: u16,
    ) -> Result<Float, LirExecutorError> {
        let sort = self.float_sort(bits)?;
        let ctx = value.get_ctx();
        let rm = RoundingMode::round_nearest_ties_to_even();
        let ast = unsafe {
            z3_sys::Z3_mk_fpa_to_fp_signed(
                ctx.get_z3_context(),
                rm.get_z3_ast(),
                value.get_z3_ast(),
                sort.get_z3_sort(),
            )
            .ok_or_else(|| {
                LirExecutorError::solver("failed to convert signed bitvector to float")
            })?
        };
        Ok(unsafe { <Float as Ast>::wrap(ctx, ast) })
    }

    pub(crate) fn unsigned_bv_to_float(
        &self,
        value: &BV,
        bits: u16,
    ) -> Result<Float, LirExecutorError> {
        let sort = self.float_sort(bits)?;
        let ctx = value.get_ctx();
        let rm = RoundingMode::round_nearest_ties_to_even();
        let ast = unsafe {
            z3_sys::Z3_mk_fpa_to_fp_unsigned(
                ctx.get_z3_context(),
                rm.get_z3_ast(),
                value.get_z3_ast(),
                sort.get_z3_sort(),
            )
            .ok_or_else(|| {
                LirExecutorError::solver("failed to convert unsigned bitvector to float")
            })?
        };
        Ok(unsafe { <Float as Ast>::wrap(ctx, ast) })
    }

    pub(crate) fn float_to_signed_bv(&self, value: &Float, bits: u16) -> BV {
        value.to_sbv_with_rounding_mode(&RoundingMode::round_towards_zero(), bits as u32)
    }

    pub(crate) fn float_to_unsigned_bv(&self, value: &Float, bits: u16) -> BV {
        value.to_ubv_with_rounding_mode(&RoundingMode::round_towards_zero(), bits as u32)
    }

    pub(crate) fn float_cast(&self, value: &Float, bits: u16) -> Result<Float, LirExecutorError> {
        let sort = self.float_sort(bits)?;
        Ok(value.to_fp_with_rounding_mode(&RoundingMode::round_nearest_ties_to_even(), &sort))
    }

    pub(crate) fn float_sort(&self, bits: u16) -> Result<Sort, LirExecutorError> {
        match bits {
            16 => Ok(Sort::float(5, 11)),
            32 => Ok(Sort::float32()),
            64 => Ok(Sort::double()),
            80 => Ok(Sort::float(15, 65)),
            128 => Ok(Sort::float(15, 113)),
            _ => Err(LirExecutorError::UnsupportedExpression(
                "floating-point width",
            )),
        }
    }
}
