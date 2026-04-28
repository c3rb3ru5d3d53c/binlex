use super::helpers::{render_location, sanitize_symbol};
use super::LoweringContext;
use crate::lifters::llvm::abi::coerce_int_value_width;
use crate::semantics::SemanticLocation;
use inkwell::attributes::Attribute;
use inkwell::types::{AnyType, IntType};
use inkwell::values::{IntValue, PointerValue};
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn slot_for_location(
        &mut self,
        location: &SemanticLocation,
    ) -> Result<PointerValue<'ctx>, Error> {
        let key = render_location(location);
        if let Some(slot) = self.slots.get(&key) {
            return Ok(*slot);
        }
        if let Some((parent_name, parent_bits, _)) = self.x86_parent_register_alias(location) {
            let parent = SemanticLocation::Register {
                name: parent_name,
                bits: parent_bits,
            };
            let parent_key = render_location(&parent);
            if !self.slots.contains_key(&parent_key) {
                let _ = self.slot_for_location(&parent)?;
            }
        }
        let ty = self.location_type(location);
        let slot = self.build_entry_alloca(ty, &sanitize_symbol(&key))?;
        let initial = self.initial_location_value(location)?;
        self.builder
            .build_store(slot, initial)
            .map_err(|err| Error::other(err.to_string()))?;
        self.slots.insert(key, slot);
        self.slot_locations
            .insert(render_location(location), location.clone());
        Ok(slot)
    }

    pub(super) fn merge_partial_register_write(
        &mut self,
        name: &str,
        bits: u16,
        value: IntValue<'ctx>,
    ) -> Result<(), Error> {
        let location = SemanticLocation::Register {
            name: name.to_string(),
            bits,
        };
        let Some((parent_name, parent_bits, shift)) = self.x86_parent_register_alias(&location)
        else {
            return Ok(());
        };
        let parent = SemanticLocation::Register {
            name: parent_name,
            bits: parent_bits,
        };
        let parent_slot = self.slot_for_location(&parent)?;
        let parent_key = render_location(&parent);
        let parent_value = self
            .builder
            .build_load(self.int_type(parent_bits), parent_slot, "partial_parent")
            .map_err(|err| Error::other(err.to_string()))?
            .into_int_value();
        let parent_type = self.int_type(parent_bits);
        let value = coerce_int_value_width(
            &self.builder,
            value,
            parent_type,
            "partial_merge_zext",
            "partial_merge_trunc",
        )?;
        let shifted = if shift == 0 {
            value
        } else {
            self.builder
                .build_left_shift(
                    value,
                    parent_type.const_int(shift as u64, false),
                    "partial_shift",
                )
                .map_err(|err| Error::other(err.to_string()))?
        };
        let bit_mask = if bits == 64 {
            u64::MAX
        } else {
            ((1u64 << bits) - 1) << shift
        };
        let cleared = self
            .builder
            .build_and(
                parent_value,
                parent_type.const_int(!bit_mask, false),
                "partial_cleared",
            )
            .map_err(|err| Error::other(err.to_string()))?;
        let merged = self
            .builder
            .build_or(cleared, shifted, "partial_merged")
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(parent_slot, merged)
            .map_err(|err| Error::other(err.to_string()))?;
        self.written_locations.insert(parent_key);
        Ok(())
    }

    fn initial_location_value(&self, location: &SemanticLocation) -> Result<IntValue<'ctx>, Error> {
        match location {
            SemanticLocation::Register { name, bits } => self
                .read_native_register(name, *bits)
                .or_else(|_| Ok(self.int_type(*bits).const_zero())),
            SemanticLocation::Flag { name, bits } => self
                .read_native_flag(name, *bits)
                .or_else(|_| Ok(self.int_type(*bits).const_zero())),
            _ => Ok(self.location_type(location).const_zero()),
        }
    }

    pub(super) fn build_entry_alloca(
        &self,
        ty: IntType<'ctx>,
        name: &str,
    ) -> Result<PointerValue<'ctx>, Error> {
        let entry = self
            .function
            .get_first_basic_block()
            .expect("function should have entry block");
        let builder = self.context.create_builder();
        if let Some(first) = entry.get_first_instruction() {
            builder.position_before(&first);
        } else {
            builder.position_at_end(entry);
        }
        builder
            .build_alloca(ty, name)
            .map_err(|err| Error::other(err.to_string()))
    }

    pub(super) fn elementtype_attribute(&self, ty: IntType<'ctx>) -> Attribute {
        let kind_id = Attribute::get_named_enum_kind_id("elementtype");
        self.context
            .create_type_attribute(kind_id, ty.as_any_type_enum())
    }
}
