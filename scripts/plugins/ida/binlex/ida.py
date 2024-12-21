
import idc
import idaapi
import ida_bytes
import idautils
import ida_ua
import ida_kernwin
import ida_nalt

class IDA():
    @staticmethod
    def get_bytes(ea: int, size: int) -> bytes | None:
        return ida_bytes.get_bytes(ea, size)

    @staticmethod
    def file_attribute():
        return {
            'type': 'file',
            'sha256': ida_nalt.retrieve_input_file_sha256().hex(),
            'tlsh': None,
            'size': None,
            'entropy': None,
        }

    @staticmethod
    def get_functions() -> list:
        return [idaapi.get_func(ea) for ea in idautils.Functions()]

    @staticmethod
    def get_function_name(ea: int) -> str:
        return idc.get_func_name(ea)

    @staticmethod
    def get_function_blocks(function) -> list:
        return [block for block in idaapi.FlowChart(function)]

    @staticmethod
    def get_block_instructions(block) -> list:
        instructions = []
        ea = block.start_ea
        while ea < block.end_ea:
            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, ea)
            instructions.append(insn)
            ea += insn.size
        return instructions

    @staticmethod
    def get_function_addresses(functions):
        return [function.start_ea for function in functions]

    @staticmethod
    def get_disassembly_selection_range():
        status, start_addr, end_addr = ida_kernwin.read_range_selection(ida_kernwin.get_current_viewer())
        if status is True:
            return (start_addr, end_addr)
        current_screen_ea = ida_kernwin.get_screen_ea()
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, current_screen_ea):
            next_instr_ea = current_screen_ea + insn.size
        else:
            next_instr_ea = current_screen_ea
        return (current_screen_ea, next_instr_ea)

    @staticmethod
    def get_instruction_addresses():
        instruction_addresses = []
        for seg_ea in idautils.Segments():
            start = idc.get_segm_start(seg_ea)
            end = idc.get_segm_end(seg_ea)
            ea = start
            while ea < end:
                if idc.is_code(idc.get_full_flags(ea)):
                    instruction_addresses.append(ea)
                ea = idc.next_head(ea, end)
        return instruction_addresses
