import re
import pickle
import idc
import idaapi
import ida_bytes
import idautils
import ida_ua
import ida_kernwin
import ida_nalt
import ida_registry
import ida_funcs

class IDA():

    def __init__(self):
        pass

    @staticmethod
    def get_database_sha256():
        return ida_nalt.retrieve_input_file_sha256().hex()

    @staticmethod
    def get_bytes(ea: int, size: int) -> bytes | None:
        result = None
        def thunk_get_bytes():
            nonlocal result
            result = idaapi.get_bytes(ea, size)
        ida_kernwin.execute_sync(thunk_get_bytes, ida_kernwin.MFF_READ)
        return result

    @staticmethod
    def file_attribute():
        return {
            'type': 'file',
            'sha256': ida_nalt.retrieve_input_file_sha256().hex(),
            'tlsh': None,
            'size': None,
            'entropy': None,
        }

    def set_name(self, ea: int, name: str):
        name = self.normalize_function_name(name)
        idaapi.set_name(ea, name, idaapi.SN_FORCE)

    @staticmethod
    def normalize_function_name(name: str) -> str:
        normalized = re.sub(r'[^0-9A-Za-z_]', '_', name)
        normalized = re.sub(r'_+', '_', normalized)
        if re.match(r'^\d', normalized):
            normalized = f'_{normalized}'
        return normalized

    def get_function_names(self):
        function_names = {}
        for function in self.get_functions():
            function_names[function.start_ea] = self.get_function_name(function.start_ea)
        return function_names

    @staticmethod
    def set_function_comment(ea: int, comment: str, repeatable: bool = True):
        f = idaapi.get_func(ea)
        idaapi.set_func_cmt(f, comment, repeatable)

    def delete_function_comment(self, ea: int, repeatable: bool = True):
        self.set_function_comment(ea, '', repeatable=repeatable)

    @staticmethod
    def get_functions() -> list:
        return [idaapi.get_func(ea) for ea in idautils.Functions()]

    @staticmethod
    def get_function_name(ea: int) -> str:
        name =  idc.get_func_name(ea)
        if name is None: return ''
        return name

    @staticmethod
    def get_basic_block(ea: int):
        function = idaapi.get_func(ea)
        if function is None: return None
        for block in idaapi.FlowChart(function):
            if block.start_ea <= ea < block.end_ea:
                return block

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

    @staticmethod
    def set_registry_value(key: str, value, subkey: str = 'binlex'):
        serialized_value = pickle.dumps(value)
        ida_registry.reg_write_binary(key, serialized_value, subkey=subkey)

    @staticmethod
    def get_registry_value(key: str, subkey: str = 'binlex'):
        value = ida_registry.reg_read_binary(key, subkey=subkey)
        if value is None:
            return None

        try:
            return pickle.loads(value)
        except (pickle.UnpicklingError, TypeError):
            return None

    @staticmethod
    def delete_registry_value(key: str, subkey: str = 'binlex'):
        ida_registry.reg_delete(key, subkey=subkey)
