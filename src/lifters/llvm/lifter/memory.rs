use super::LoweringContext;
use crate::lifters::llvm::abi::coerce_int_value_width;
use crate::semantics::{SemanticAddressSpace, SemanticExpression};
use inkwell::IntPredicate;
use inkwell::values::{IntValue, PointerValue};
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn try_direct_load(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        bits: u16,
    ) -> Result<Option<IntValue<'ctx>>, Error> {
        if !matches!(
            space,
            SemanticAddressSpace::Default | SemanticAddressSpace::Stack
        ) {
            return Ok(None);
        }
        let ptr = self.direct_pointer_from_expression(addr)?;
        let value = self
            .builder
            .build_load(self.int_type(bits), ptr, "direct_loadtmp")
            .map_err(|err| Error::other(err.to_string()))?
            .into_int_value();
        Ok(Some(value))
    }

    pub(super) fn try_direct_store(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        expression: &SemanticExpression,
        bits: u16,
    ) -> Result<Option<()>, Error> {
        if !matches!(
            space,
            SemanticAddressSpace::Default | SemanticAddressSpace::Stack
        ) {
            return Ok(None);
        }
        let ptr = self.direct_pointer_from_expression(addr)?;
        let value = self.lower_expression(expression)?;
        let value = coerce_int_value_width(
            &self.builder,
            value,
            self.int_type(bits),
            "direct_store_zext",
            "direct_store_trunc",
        )?;
        self.builder
            .build_store(ptr, value)
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(Some(()))
    }

    pub(super) fn try_direct_memory_set(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        value: &SemanticExpression,
        count: &SemanticExpression,
        element_bits: u16,
        decrement: &SemanticExpression,
    ) -> Result<bool, Error> {
        if !matches!(space, SemanticAddressSpace::Default) {
            return Ok(false);
        }

        let pointer_int_type = self.pointer_int_type();
        let lowered_addr = self.lower_expression(addr)?;
        let base_addr = coerce_int_value_width(
            &self.builder,
            lowered_addr,
            pointer_int_type,
            "memset_addr_zext",
            "memset_addr_trunc",
        )?;
        let lowered_count = self.lower_expression(count)?;
        let count = coerce_int_value_width(
            &self.builder,
            lowered_count,
            pointer_int_type,
            "memset_count_zext",
            "memset_count_trunc",
        )?;
        let lowered_decrement = self.lower_expression(decrement)?;
        let decrement = self.to_bool(lowered_decrement);
        let lowered_value = self.lower_expression(value)?;
        let value = coerce_int_value_width(
            &self.builder,
            lowered_value,
            self.int_type(element_bits),
            "memset_value_zext",
            "memset_value_trunc",
        )?;
        self.build_counted_memory_loop(
            "memset",
            base_addr,
            None,
            count,
            element_bits,
            decrement,
            |this, dst_ptr, _| {
                this.builder
                    .build_store(dst_ptr, value)
                    .map_err(|err| Error::other(err.to_string()))?;
                Ok(())
            },
        )?;
        Ok(true)
    }

    pub(super) fn try_direct_memory_copy(
        &mut self,
        src_space: &SemanticAddressSpace,
        src_addr: &SemanticExpression,
        dst_space: &SemanticAddressSpace,
        dst_addr: &SemanticExpression,
        count: &SemanticExpression,
        element_bits: u16,
        decrement: &SemanticExpression,
    ) -> Result<bool, Error> {
        if !matches!(src_space, SemanticAddressSpace::Default)
            || !matches!(dst_space, SemanticAddressSpace::Default)
        {
            return Ok(false);
        }

        let pointer_int_type = self.pointer_int_type();
        let lowered_src_addr = self.lower_expression(src_addr)?;
        let src_addr = coerce_int_value_width(
            &self.builder,
            lowered_src_addr,
            pointer_int_type,
            "memcpy_src_zext",
            "memcpy_src_trunc",
        )?;
        let lowered_dst_addr = self.lower_expression(dst_addr)?;
        let dst_addr = coerce_int_value_width(
            &self.builder,
            lowered_dst_addr,
            pointer_int_type,
            "memcpy_dst_zext",
            "memcpy_dst_trunc",
        )?;
        let lowered_count = self.lower_expression(count)?;
        let count = coerce_int_value_width(
            &self.builder,
            lowered_count,
            pointer_int_type,
            "memcpy_count_zext",
            "memcpy_count_trunc",
        )?;
        let lowered_decrement = self.lower_expression(decrement)?;
        let decrement = self.to_bool(lowered_decrement);
        self.build_counted_memory_loop(
            "memcpy",
            dst_addr,
            Some(src_addr),
            count,
            element_bits,
            decrement,
            |this, dst_ptr, src_ptr| {
                let src_ptr = src_ptr.expect("memory copy loop requires a source pointer");
                let value = this
                    .builder
                    .build_load(this.int_type(element_bits), src_ptr, "memcpy_load")
                    .map_err(|err| Error::other(err.to_string()))?;
                this.builder
                    .build_store(dst_ptr, value)
                    .map_err(|err| Error::other(err.to_string()))?;
                Ok(())
            },
        )?;
        Ok(true)
    }

    fn build_counted_memory_loop<F>(
        &mut self,
        loop_name: &str,
        dst_base: IntValue<'ctx>,
        src_base: Option<IntValue<'ctx>>,
        count: IntValue<'ctx>,
        element_bits: u16,
        decrement: IntValue<'ctx>,
        mut body: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&mut Self, PointerValue<'ctx>, Option<PointerValue<'ctx>>) -> Result<(), Error>,
    {
        let pointer_int_type = self.pointer_int_type();
        let element_bytes = pointer_int_type.const_int((element_bits / 8) as u64, false);
        let zero = pointer_int_type.const_zero();
        let one = pointer_int_type.const_int(1, false);

        let current_block = self
            .builder
            .get_insert_block()
            .ok_or_else(|| Error::other("memory loop requires an insertion block"))?;
        let loop_cond = self
            .context
            .append_basic_block(self.function, &format!("{loop_name}_cond"));
        let loop_body = self
            .context
            .append_basic_block(self.function, &format!("{loop_name}_body"));
        let loop_exit = self
            .context
            .append_basic_block(self.function, &format!("{loop_name}_exit"));

        self.builder.position_at_end(current_block);
        let index_slot = self
            .builder
            .build_alloca(pointer_int_type, &format!("{loop_name}_index"))
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(index_slot, zero)
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_unconditional_branch(loop_cond)
            .map_err(|err| Error::other(err.to_string()))?;

        self.builder.position_at_end(loop_cond);
        let index = self
            .builder
            .build_load(
                pointer_int_type,
                index_slot,
                &format!("{loop_name}_index_load"),
            )
            .map_err(|err| Error::other(err.to_string()))?
            .into_int_value();
        let keep_going = self
            .builder
            .build_int_compare(
                IntPredicate::ULT,
                index,
                count,
                &format!("{loop_name}_keep_going"),
            )
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_conditional_branch(keep_going, loop_body, loop_exit)
            .map_err(|err| Error::other(err.to_string()))?;

        self.builder.position_at_end(loop_body);
        let offset = self
            .builder
            .build_int_mul(index, element_bytes, &format!("{loop_name}_offset"))
            .map_err(|err| Error::other(err.to_string()))?;
        let dst_addr = self.directional_memory_address(
            dst_base,
            offset,
            decrement,
            &format!("{loop_name}_dst"),
        )?;
        let dst_ptr = self
            .builder
            .build_int_to_ptr(
                dst_addr,
                self.context.ptr_type(inkwell::AddressSpace::default()),
                &format!("{loop_name}_dst_ptr"),
            )
            .map_err(|err| Error::other(err.to_string()))?;
        let src_ptr = if let Some(src_base) = src_base {
            let src_addr = self.directional_memory_address(
                src_base,
                offset,
                decrement,
                &format!("{loop_name}_src"),
            )?;
            Some(
                self.builder
                    .build_int_to_ptr(
                        src_addr,
                        self.context.ptr_type(inkwell::AddressSpace::default()),
                        &format!("{loop_name}_src_ptr"),
                    )
                    .map_err(|err| Error::other(err.to_string()))?,
            )
        } else {
            None
        };
        body(self, dst_ptr, src_ptr)?;
        let next_index = self
            .builder
            .build_int_add(index, one, &format!("{loop_name}_next_index"))
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(index_slot, next_index)
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_unconditional_branch(loop_cond)
            .map_err(|err| Error::other(err.to_string()))?;

        self.builder.position_at_end(loop_exit);
        Ok(())
    }

    fn directional_memory_address(
        &self,
        base: IntValue<'ctx>,
        offset: IntValue<'ctx>,
        decrement: IntValue<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>, Error> {
        let forward = self
            .builder
            .build_int_add(base, offset, &format!("{name}_forward"))
            .map_err(|err| Error::other(err.to_string()))?;
        let backward = self
            .builder
            .build_int_sub(base, offset, &format!("{name}_backward"))
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_select(decrement, backward, forward, &format!("{name}_select"))
            .map_err(|err| Error::other(err.to_string()))
            .map(|value| value.into_int_value())
    }

    fn direct_pointer_from_expression(
        &mut self,
        expression: &SemanticExpression,
    ) -> Result<PointerValue<'ctx>, Error> {
        let address = self.lower_expression(expression)?;
        let pointer_int_type = self.pointer_int_type();
        let address = coerce_int_value_width(
            &self.builder,
            address,
            pointer_int_type,
            "direct_ptr_zext",
            "direct_ptr_trunc",
        )?;
        self.builder
            .build_int_to_ptr(
                address,
                self.context.ptr_type(inkwell::AddressSpace::default()),
                "direct_ptr",
            )
            .map_err(|err| Error::other(err.to_string()))
    }
}
