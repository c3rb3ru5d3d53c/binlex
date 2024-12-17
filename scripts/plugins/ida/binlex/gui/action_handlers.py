import ida_kernwin
import idaapi

class BinlexExportActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.export()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class CopyMinHashActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_minhash()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyPatternActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_pattern()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyHexActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_hex()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class ScanMinHashActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_scan_minhash()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class ScanTLSHActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_scan_tlsh()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

class CopyTLSHActionHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.action_copy_tlsh()
        return 1

    def update(self, ctx):
        if ctx.widget and ida_kernwin.get_widget_type(ctx.widget) in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DISASM]:
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE

def register_action_handlers(parent):
    action_desc = idaapi.action_desc_t(
        "binlex:copy_pattern",
        "Copy Pattern",
        CopyPatternActionHandler(parent),
        None,
        "Copy selected range as pattern",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_pattern action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_hex",
        "Copy Hex",
        CopyHexActionHandler(parent),
        None,
        "Copy selected range as hex",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_minhash action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_minhash",
        "Copy MinHash",
        CopyMinHashActionHandler(parent),
        None,
        "Copy selected range as a MinHash",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_minhash action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:scan_minhash",
        "Scan MinHash",
        ScanMinHashActionHandler(parent),
        None,
        "Scan project for MinHash similarity matches",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register scan_minhash action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:copy_tlsh",
        "Copy TLSH",
        CopyTLSHActionHandler(parent),
        None,
        "Copy selected range as TLSH",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register copy_tlsh action.\n')
    action_desc = idaapi.action_desc_t(
        "binlex:scan_tlsh",
        "Scan TLSH",
        ScanTLSHActionHandler(parent),
        None,
        "Scan project for TLSH similarity matches",
        -1
    )
    if not ida_kernwin.register_action(action_desc): ida_kernwin.msg('[x] failed to register scan_tlsh action.\n')