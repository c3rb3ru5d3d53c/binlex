use super::LoweringContext;
use crate::Architecture;
use crate::semantics::{SemanticExpression, SemanticLocation};
use inkwell::IntPredicate;
use inkwell::basic_block::BasicBlock;
use inkwell::types::{FloatType, IntType};
use inkwell::values::{FloatValue, IntValue};
use std::collections::HashMap;
use std::io::Error;
use std::num::NonZeroU32;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn int_type(&self, bits: u16) -> IntType<'ctx> {
        match bits {
            0 | 1 => self.context.bool_type(),
            8 => self.context.i8_type(),
            16 => self.context.i16_type(),
            32 => self.context.i32_type(),
            64 => self.context.i64_type(),
            128 => self.context.i128_type(),
            n => self
                .context
                .custom_width_int_type(NonZeroU32::new(n as u32).expect("non-zero width"))
                .expect("valid integer width"),
        }
    }

    pub(super) fn float_type(&self, bits: u16) -> Result<FloatType<'ctx>, Error> {
        match bits {
            32 => Ok(self.context.f32_type()),
            64 => Ok(self.context.f64_type()),
            _ => Err(Error::other(format!(
                "unsupported floating-point width for llvm lowering: {}",
                bits
            ))),
        }
    }

    pub(super) fn int_bits_to_float(
        &self,
        value: IntValue<'ctx>,
        float_type: FloatType<'ctx>,
        name: &str,
    ) -> Result<FloatValue<'ctx>, Error> {
        self.builder
            .build_bit_cast(value, float_type, name)
            .map_err(|err| Error::other(err.to_string()))
            .map(|value| value.into_float_value())
    }

    pub(super) fn float_to_int_bits(
        &self,
        value: FloatValue<'ctx>,
        int_type: IntType<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>, Error> {
        self.builder
            .build_bit_cast(value, int_type, name)
            .map_err(|err| Error::other(err.to_string()))
            .map(|value| value.into_int_value())
    }

    pub(super) fn pointer_int_type(&self) -> IntType<'ctx> {
        match self.architecture {
            Architecture::AMD64 | Architecture::ARM64 => self.context.i64_type(),
            _ => self.context.i32_type(),
        }
    }

    pub(super) fn location_type(&self, location: &SemanticLocation) -> IntType<'ctx> {
        self.int_type(match location {
            SemanticLocation::Register { bits, .. } => *bits,
            SemanticLocation::Flag { bits, .. } => *bits,
            SemanticLocation::ProgramCounter { bits } => *bits,
            SemanticLocation::Temporary { bits, .. } => *bits,
            SemanticLocation::Memory { bits, .. }
            | SemanticLocation::IndexedMemory { bits, .. }
            | SemanticLocation::StackMemory { bits, .. } => *bits,
        })
    }

    pub(super) fn to_i64(&self, value: IntValue<'ctx>) -> IntValue<'ctx> {
        match value.get_type().get_bit_width().cmp(&64) {
            std::cmp::Ordering::Equal => value,
            std::cmp::Ordering::Less => self
                .builder
                .build_int_z_extend(value, self.context.i64_type(), "zext64")
                .expect("zext"),
            std::cmp::Ordering::Greater => self
                .builder
                .build_int_truncate(value, self.context.i64_type(), "trunc64")
                .expect("trunc"),
        }
    }

    pub(super) fn to_bool(&self, value: IntValue<'ctx>) -> IntValue<'ctx> {
        if value.get_type().get_bit_width() == 1 {
            value
        } else {
            self.builder
                .build_int_compare(
                    IntPredicate::NE,
                    value,
                    value.get_type().const_zero(),
                    "tobool",
                )
                .expect("bool")
        }
    }

    pub(super) fn resolve_block_target(
        &self,
        expression: &SemanticExpression,
        block_map: &HashMap<u64, BasicBlock<'ctx>>,
    ) -> Option<BasicBlock<'ctx>> {
        let address = match expression {
            SemanticExpression::Const { value, .. } => u64::try_from(*value).ok()?,
            _ => return None,
        };
        block_map.get(&address).copied()
    }
}
