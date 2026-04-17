"""Core logic for YARA pattern generation from IDA instructions"""
from __future__ import annotations

import ida_bytes
import ida_kernwin
import ida_ua
import idaapi
import idc


class InstructionData:
    """Represents a single parsed instruction with wildcard state"""

    def __init__(self, address: int):
        self.address = address
        self.size = 0
        self.raw_bytes = b""
        self.mnemonic = ""
        self.operands: list[str] = []
        self.operand_types: list[int] = []

        # Wildcard masks
        self.wildcard_mnemonic = False
        self.wildcard_operands: list[bool] = []

        # Nibble-level mask for fine-grained control
        # 0xFF = both nibbles kept (byte shown as "DE")
        # 0xF0 = high nibble kept, low wildcarded ("D?")
        # 0x0F = low nibble kept, high wildcarded ("?E")
        # 0x00 = both nibbles wildcarded ("??")
        self.byte_mask: list[int] = []

    def parse(self) -> bool:
        """Parse instruction at address using IDA API"""
        insn = ida_ua.insn_t()
        self.size = ida_ua.decode_insn(insn, self.address)

        if self.size == 0:
            return False

        self.raw_bytes = ida_bytes.get_bytes(self.address, self.size)
        if not self.raw_bytes:
            return False

        self.mnemonic = insn.get_canon_mnem()

        # Parse operands (IDA supports up to 8 operands)
        self.operands = []
        self.operand_types = []
        for i in range(8):
            if insn.ops[i].type == ida_ua.o_void:
                break
            # Use idc.print_operand for proper operand formatting
            op_text = idc.print_operand(self.address, i)
            if op_text:  # Only add non-empty operands
                self.operands.append(op_text)
                self.operand_types.append(insn.ops[i].type)

        self.wildcard_operands = [False] * len(self.operands)
        self.byte_mask = [0xFF] * self.size  # Default: all bytes fixed

        return True

    def _has_modrm_byte(self) -> bool:
        """Check if instruction has a ModRM byte (x86/x64 specific, heuristic for others)"""
        # This is mainly for x86/x64, but we use operand types as a generic heuristic
        for op_type in self.operand_types:
            if op_type in (ida_ua.o_reg, ida_ua.o_mem, ida_ua.o_displ,
                          ida_ua.o_phrase, ida_ua.o_reg | ida_ua.o_mem):
                return True
        return False

    def _is_fixed_width_architecture(self) -> bool:
        """Check if this is a fixed-width instruction architecture (ARM, MIPS, etc.)"""
        # Fixed-width architectures typically have consistent instruction sizes
        # ARM: 4 bytes (32-bit) or 2 bytes (Thumb)
        # MIPS: 4 bytes
        # PowerPC: 4 bytes
        # x86/x64: variable (1-15 bytes)

        # Simple heuristic: if size is 2 or 4, likely fixed-width
        return self.size in (2, 4)

    def _get_opcode_size(self) -> int:
        """
        Estimate opcode size (architecture-generic)
        For fixed-width: entire instruction is opcode+operands
        For variable-width: use heuristics
        """
        if self._is_fixed_width_architecture():
            # Fixed-width: opcode is typically first 1-2 bytes
            # ARM: bits 27-20 usually contain opcode
            # MIPS: bits 31-26 contain opcode
            return 1  # Wildcard first byte for simplicity
        else:
            # Variable-width (x86): opcode is 1-3 bytes typically
            return min(2, self.size)

    def get_masked_bytes(self) -> list[str]:
        """
        Get list of hex bytes/nibbles with wildcards applied
        Returns list like ['48', '8B', 'D?', '??']
        Supports nibble-level masking for precision
        """
        # Reset byte mask to all fixed (0xFF)
        self.byte_mask = [0xFF] * self.size

        if self.wildcard_mnemonic:
            # Wildcard opcode bytes (architecture-generic approach)
            opcode_size = self._get_opcode_size()

            if self._is_fixed_width_architecture():
                # Fixed-width architectures (ARM, MIPS, etc.)
                # Opcode and operands are packed into fixed instruction width
                # Strategy: wildcard bytes that likely contain opcode bits

                if self.size == 4:
                    # 4-byte instruction (ARM, MIPS, PowerPC)
                    # Typically: opcode in high bits, operands in low bits
                    # Wildcard first 1-2 bytes (contains most opcode bits)
                    self.byte_mask[0] = 0x00
                    if opcode_size > 1:
                        self.byte_mask[1] = 0x00
                elif self.size == 2:
                    # 2-byte instruction (Thumb, compressed RISC-V)
                    # Wildcard first byte
                    self.byte_mask[0] = 0x00
            else:
                # Variable-width architectures (x86/x64)
                # Opcode is separate from operands in byte stream
                for i in range(opcode_size):
                    if i < self.size:
                        self.byte_mask[i] = 0x00

        # Apply operand wildcards (architecture-generic)
        for i, should_wildcard in enumerate(self.wildcard_operands):
            if should_wildcard and i < len(self.operand_types):
                op_type = self.operand_types[i]

                if op_type in (ida_ua.o_imm, ida_ua.o_near, ida_ua.o_far):
                    # Immediates and addresses: wildcard appropriate bytes
                    if self._is_fixed_width_architecture():
                        # Fixed-width: immediate is packed in instruction
                        # Wildcard lower bytes (typically where immediates are)
                        if self.size == 4:
                            # Wildcard last 2 bytes (common for immediates)
                            self.byte_mask[2] = 0x00
                            self.byte_mask[3] = 0x00
                        elif self.size == 2:
                            # Wildcard last byte
                            self.byte_mask[1] = 0x00
                    else:
                        # Variable-width: immediate at end
                        bytes_to_wildcard = min(4, max(1, self.size - 2))
                        for j in range(self.size - bytes_to_wildcard, self.size):
                            self.byte_mask[j] = 0x00

                elif op_type in (ida_ua.o_mem, ida_ua.o_displ, ida_ua.o_phrase):
                    # Memory operands
                    if self._is_fixed_width_architecture():
                        # Fixed-width: address/offset packed in instruction
                        # Wildcard middle-to-end bytes
                        start_idx = 1 if self.size <= 2 else 2
                        for j in range(start_idx, self.size):
                            self.byte_mask[j] = 0x00
                    else:
                        # Variable-width (x86): ModRM + displacement
                        # Wildcard from byte 1 onward (after opcode)
                        for j in range(1, self.size):
                            self.byte_mask[j] = 0x00

                elif op_type == ida_ua.o_reg:
                    # Register operands
                    if self._is_fixed_width_architecture():
                        # Fixed-width: registers in specific bit fields
                        # For ARM/MIPS: often in bits 15-12, 11-8, etc.
                        # Wildcard bytes containing register fields
                        if self.size >= 2:
                            self.byte_mask[1] = 0x00
                        if self.size >= 4:
                            self.byte_mask[2] = 0x00
                    else:
                        # Variable-width (x86): in ModRM byte
                        if self.size > 1:
                            self.byte_mask[1] = 0x00

                else:
                    # Default: wildcard last half of instruction
                    start_idx = max(1, self.size // 2)
                    for j in range(start_idx, self.size):
                        self.byte_mask[j] = 0x00

        # Generate output with nibble-level masks applied
        result = []
        for i, byte_val in enumerate(self.raw_bytes):
            mask = self.byte_mask[i]

            if mask == 0xFF:
                # Both nibbles kept: "DE"
                result.append(f'{byte_val:02X}')
            elif mask == 0xF0:
                # High nibble kept, low wildcarded: "D?"
                high_nibble = (byte_val >> 4) & 0x0F
                result.append(f'{high_nibble:X}?')
            elif mask == 0x0F:
                # Low nibble kept, high wildcarded: "?E"
                low_nibble = byte_val & 0x0F
                result.append(f'?{low_nibble:X}')
            else:  # 0x00
                # Both nibbles wildcarded: "??"
                result.append('??')

        return result


class YaraPatternGenerator:
    """Generates YARA hex patterns from a sequence of instructions"""

    def __init__(self, start_ea: int, end_ea: int):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.instructions: list[InstructionData] = []
        self._parse_instructions()

    def _parse_instructions(self) -> None:
        """Parse all instructions in the range"""
        current_ea = self.start_ea

        while current_ea < self.end_ea:
            insn_data = InstructionData(current_ea)
            if insn_data.parse():
                self.instructions.append(insn_data)
                current_ea += insn_data.size
            else:
                # Skip to next byte if parse failed
                current_ea += 1

    def set_wildcard_mnemonic(self, index: int, wildcard: bool) -> None:
        """Set wildcard state for mnemonic at instruction index"""
        if 0 <= index < len(self.instructions):
            self.instructions[index].wildcard_mnemonic = wildcard

    def set_wildcard_operand(self, insn_index: int, op_index: int, wildcard: bool) -> None:
        """Set wildcard state for operand at instruction and operand index"""
        if 0 <= insn_index < len(self.instructions):
            insn = self.instructions[insn_index]
            if 0 <= op_index < len(insn.wildcard_operands):
                insn.wildcard_operands[op_index] = wildcard

    def to_yara_pattern(self) -> str:
        """
        Generate YARA hex pattern string
        Returns: "48 8B ?? ?? 48 89 ??"
        """
        all_bytes = []

        for insn in self.instructions:
            masked_bytes = insn.get_masked_bytes()
            all_bytes.extend(masked_bytes)

        if not all_bytes:
            return ""

        return " ".join(all_bytes)

    def to_yara_rule(self, rule_name: str = "generated_rule") -> str:
        """
        Generate complete YARA rule
        Returns full YARA rule with boilerplate
        """
        pattern = self.to_yara_pattern()

        rule = f"rule {rule_name}\n"
        rule += "{\n"
        rule += "    strings:\n"
        rule += f"        $pattern = {pattern}\n"
        rule += "\n"
        rule += "    condition:\n"
        rule += "        $pattern\n"
        rule += "}\n"

        return rule

    def get_statistics(self) -> dict:
        """
        Calculate pattern statistics
        Returns: dict with total_nibbles, fixed_nibbles, wildcarded_nibbles, specificity
        """
        total_nibbles = 0
        wildcarded_nibbles = 0

        for insn in self.instructions:
            masked = insn.get_masked_bytes()
            for byte_str in masked:
                if byte_str == '??':
                    # Both nibbles wildcarded
                    wildcarded_nibbles += 2
                    total_nibbles += 2
                elif '?' in byte_str:
                    # One nibble wildcarded (e.g., 'D?' or '?E')
                    wildcarded_nibbles += 1
                    total_nibbles += 2
                else:
                    # Both nibbles fixed (e.g., 'DE')
                    total_nibbles += 2

        fixed_nibbles = total_nibbles - wildcarded_nibbles
        specificity = (fixed_nibbles / total_nibbles * 100) if total_nibbles > 0 else 0

        return {
            'total_nibbles': total_nibbles,
            'fixed_nibbles': fixed_nibbles,
            'wildcarded_nibbles': wildcarded_nibbles,
            'specificity': specificity
        }

    def reset_wildcards(self) -> None:
        """Reset all wildcards to unchecked state"""
        for insn in self.instructions:
            insn.wildcard_mnemonic = False
            insn.wildcard_operands = [False] * len(insn.operands)
            insn.byte_mask = [0xFF] * insn.size

    def wildcard_all_operands(self) -> None:
        """Set all operands to wildcarded"""
        for insn in self.instructions:
            insn.wildcard_operands = [True] * len(insn.operands)

    def wildcard_all_mnemonics(self) -> None:
        """Set all mnemonics to wildcarded"""
        for insn in self.instructions:
            insn.wildcard_mnemonic = True
