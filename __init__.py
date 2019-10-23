from binaryninja import *
import re
import traceback


__author__     = 'zznop'
__copyright__  = 'Copyright 2019, zznop'
__license__    = 'GPL'
__version__    = '1.0'
__email__      = 'zznop0x90@gmail.com'


def cond_branch(il, cond, dest):
    """
    Creates a llil conditional branch expression

    :param il: LLIL object
    :param cond: Flag condition
    :param dest: Branch destination
    """

    t = il.get_label_for_address(Architecture['Brainfuck'], il[dest].constant)
    if t is None:
        t = LowLevelILLabel()
    f = il.get_label_for_address(Architecture['Brainfuck'], il.current_address+1)
    if f is None:
        f = LowLevelILLabel()
    il.append(il.if_expr(cond, t, f))


class Brainfuck(Architecture):
    """
    This class is responsible for disassembling and lifting Brainfuck code
    """

    name             = 'Brainfuck'
    address_size     = 1
    default_int_size = 1
    instr_alignment  = 1
    max_instr_length = 1
    regs = {
        'sp' : function.RegisterInfo('sp', 1), # Not used, but required
        'cp' : function.RegisterInfo('cp', 1), # Cell pointer
    }

    stack_pointer = 'sp' # Not use, but required
    node_starts   = []
    node_ends     = []

    flags = ['z']
    flag_roles = { 'z' : FlagRole.ZeroFlagRole }
    flags_required_for_flag_condition = { LowLevelILFlagCondition.LLFC_NE : ['z'] }
    flag_write_types = ['z']
    flags_written_by_flag_write_type = { 'z' : ['z'] }

    Tokens =  {
        '+' : [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, 'inc'),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '),
            InstructionTextToken(InstructionTextTokenType.TextToken, '['),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, 'cp'),
            InstructionTextToken(InstructionTextTokenType.TextToken, ']'),
        ],
        '-' : [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, 'dec'),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '),
            InstructionTextToken(InstructionTextTokenType.TextToken, '['),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, 'cp'),
            InstructionTextToken(InstructionTextTokenType.TextToken, ']'),
        ],
        '>' : [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, 'inc'),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, 'cp'),
        ],
        '<' : [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, 'dec'),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' '),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, 'cp'),
        ],
        '[' : [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, 'nop'),
        ],
        ']' : [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, 'jnz'),
        ],
        '.' : [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, 'stdout'),
        ],
        ',' : [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, 'stdin'),
        ],
    }

    InstructionIL = {
        '+' : lambda il, value: il.store(1, il.reg(1, 'cp'), il.add(1, il.load(1, il.reg(1, 'cp')), il.const(1, 1))),
        '-' : lambda il, value: il.store(1, il.reg(1, 'cp'), il.sub(1, il.load(1, il.reg(1, 'cp')), il.const(1, 1))),
        '>' : lambda il, value: il.set_reg(1, 'cp', il.add(1, il.reg(1, 'cp'), il.const(1, 1))),
        '<' : lambda il, value: il.set_reg(1, 'cp', il.sub(1, il.reg(1, 'cp'), il.const(1, 1)), flags='z'),
        '[' : lambda il, value: il.nop(),
        ']' : lambda il, value: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_NE), il.const(4, value)),
        '.' : lambda il, value: il.system_call(),
        ',' : lambda il, value: il.system_call(),
    }

    def get_instruction_info(self, data, addr):
        """
        Provide information on branch operations

        :param data: Opcode data
        :param addr: Start address of data
        """

        if isinstance(data, bytes):
            data = data.decode()

        res = function.InstructionInfo()
        res.length = 1
        if data == ']':
            Brainfuck.node_ends.append(addr)
            res.add_branch(BranchType.FalseBranch, addr+1)
            res.add_branch(BranchType.TrueBranch,  Brainfuck.node_starts[Brainfuck.node_ends.index(addr)])
        elif data == '[':
            Brainfuck.node_starts.append(addr)
        return res

    def get_instruction_text(self, data, addr):
        """
        Get tokens used to display instruction disassembly

        :param data: Opcode data
        :param addr: Start address of data
        """

        if isinstance(data, bytes):
            data = data.decode()

        tokens = Brainfuck.Tokens.get(data, None)
        return (tokens, 1)

    def get_instruction_low_level_il(self, data, addr, il):
        """
        Lift instructions to LLIL

        :param data: Opcode data
        :param addr: Start address of data
        :param il: LLIL object
        """

        if isinstance(data, bytes):
            data = data.decode()

        value = None
        data = data[0]
        if data == ']':
            value = Brainfuck.node_starts[Brainfuck.node_ends.index(addr)]

        instr = Brainfuck.InstructionIL[data](il, value)
        if instr is not None:
            il.append(instr)

        return 1

class BrainfuckView(binaryview.BinaryView):
    """
    This class is responsible for loading Brainfuck code files
    """

    name      = 'BF'
    long_name = 'Brainfuck'

    def __init__(self, data):
        binaryview.BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['Brainfuck'].standalone_platform
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        """
        Determine if we're compatible. Ensure the file consists solely of BF
        code

        :param data: File data stream
        :return: True if our loader is compatible, False if it is not
        """

        try:
            data = data.read(0, 16).decode('utf-8')
        except UnicodeError:
            return False

        bf_re = re.compile('[+\-<>.,\[\]\n]+')
        if bf_re.match(data):
            return True

        return False

    def init(self):
        """
        Load the file and create a single code segment

        :return: True on success, False on failure
        """

        try:
            # Create code segment
            self.add_auto_segment(0, len(self.raw), 0, len(self.raw),
                SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

            # Create code section
            self.add_auto_section(
                '.text', 0, len(self.raw),
                SectionSemantics.ReadOnlyCodeSectionSemantics
            )

            # Setup the entry point
            self.add_entry_point(0)
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0, '_start'))

            return True
        except Exception:
            log.log_error(traceback.format_exc())
            return False

Brainfuck.register()
BrainfuckView.register()

