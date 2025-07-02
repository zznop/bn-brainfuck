from binaryninja import *
import re
import traceback


def cond_branch(il, cond, addr_true, addr_false):
    """
    Creates a llil conditional branch expression

    :param il: LLIL object
    :param cond: Flag condition
    :param dest: Branch destination
    """

    t = il.get_label_for_address(Architecture['Brainfuck'], addr_true)
    if t is None:
        t = LowLevelILLabel()
    f = il.get_label_for_address(Architecture['Brainfuck'], addr_false)
    if f is None:
        f = LowLevelILLabel()
    il.append(il.if_expr(cond, t, f))


class Brainfuck(Architecture):
    """
    This class is responsible for disassembling and lifting Brainfuck code
    """

    name = 'Brainfuck'
    address_size = 1
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 1
    regs = {
        'sp': function.RegisterInfo('sp', 1),  # Not used, but required
        'cp': function.RegisterInfo('cp', 1),  # Cell pointer
    }

    stack_pointer = 'sp'  # Not use, but required
    bracket_mem = {}

    flags = ['z']
    flag_roles = {'z': FlagRole.ZeroFlagRole}
    flags_required_for_flag_condition = {LowLevelILFlagCondition.LLFC_NE: ['z']}
    flag_write_types = ['z']
    flags_written_by_flag_write_type = {'z': ['z']}

    def get_addr_of_open_bracket(self, addr):
        """
        Compute address of matching '['

        :param addr: address of ']'
        """
        stack = []
        for a in sorted(Brainfuck.bracket_mem):
            if a == addr:
                return stack.pop()

            if Brainfuck.bracket_mem[a] == '[':
                stack.append(a)
            else:
                stack.pop()

    def get_instruction_info(self, data, addr):
        """
        Provide information on branch operations
        """

        if isinstance(data, bytes):
            data = data.decode()

        res = function.InstructionInfo()
        res.length = 1
        if data == '[':
            Brainfuck.bracket_mem[addr] = '['
        elif data == ']':
            Brainfuck.bracket_mem[addr] = ']'
            res.add_branch(BranchType.FalseBranch, addr + 1)
            res.add_branch(BranchType.TrueBranch,
                           self.get_addr_of_open_bracket(addr))

        return res

    def get_instruction_text(self, data, addr):
        """
        Get tokens used to display instruction disassembly
        """

        if isinstance(data, bytes):
            data = data.decode()

        tokens = []
        c = data[0]
        if c == '+':
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'inc'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(InstructionTextTokenType.TextToken, '['),
                InstructionTextToken(InstructionTextTokenType.RegisterToken,
                                     'cp'),
                InstructionTextToken(InstructionTextTokenType.TextToken, ']'),
            ]
        elif c == '-':
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'dec'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(InstructionTextTokenType.TextToken, '['),
                InstructionTextToken(InstructionTextTokenType.RegisterToken,
                                     'cp'),
                InstructionTextToken(InstructionTextTokenType.TextToken, ']'),
            ]
        elif c == '>':
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'inc'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(InstructionTextTokenType.RegisterToken,
                                     'cp'),
            ]
        elif c == '<':
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'dec'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(InstructionTextTokenType.RegisterToken,
                                     'cp'),
            ]
        elif c in ['[', '\n', ' ']:
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'nop'),
            ]
        elif c == ']':
            addr_true = self.get_addr_of_open_bracket(addr)
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'jnz'),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ' '),
                InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken,
                    'loc_%08X' % addr_true, addr_true),
            ]
        elif c == '.':
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'stdout'),
            ]
        elif c == ',':
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'stdin'),
            ]

        return (tokens, 1)

    def get_instruction_low_level_il(self, data, addr, il):
        """
        Lift instructions to LLIL
        """

        if isinstance(data, bytes):
            data = data.decode()

        expr_idx = None
        data = data[0]
        if data == '+':
            expr_idx = il.store(
                1, il.reg(1, 'cp'),
                il.add(1, il.load(1, il.reg(1, 'cp')), il.const(1, 1)))
        elif data == '-':
            expr_idx = il.store(
                1, il.reg(1, 'cp'),
                il.sub(1, il.load(1, il.reg(1, 'cp')), il.const(1, 1)))
        elif data == '>':
            expr_idx = il.set_reg(1, 'cp',
                                  il.add(1, il.reg(1, 'cp'), il.const(1, 1)))
        elif data == '<':
            expr_idx = il.set_reg(1,
                                  'cp',
                                  il.sub(1, il.reg(1, 'cp'), il.const(1, 1)),
                                  flags='z')
        elif data in ['[', ' ', '\n']:
            expr_idx = il.nop()
        elif data == ']':
            addr_true = self.get_addr_of_open_bracket(addr)
            addr_false = addr + 1
            expr_idx = cond_branch(
                il, il.flag_condition(LowLevelILFlagCondition.LLFC_NE),
                addr_true, addr_false)
        elif data in ['.', ',']:
            expr_idx = il.system_call()

        if expr_idx is not None:
            il.append(expr_idx)

        return 1


class BrainfuckView(binaryview.BinaryView):
    """
    This class is responsible for loading Brainfuck code files
    """

    name = 'BF'
    long_name = 'Brainfuck'

    def __init__(self, data):
        binaryview.BinaryView.__init__(self,
                                       parent_view=data,
                                       file_metadata=data.file)
        self.platform = Architecture['Brainfuck'].standalone_platform
        self.raw = data.read(0, data.length)

    @classmethod
    def is_valid_for_data(self, data):
        """
        Determine if we're compatible. Ensure the file consists solely of BF
        code
        """

        try:
            data = data.read(0, 16).decode('utf-8')
        except UnicodeError:
            return False

        if re.match(r'[+\-<>.,\[\]\n ]+', data):
            return True

        return False

    def init(self):
        """
        Load the file and create a single code segment
        """

        try:
            # Create code segment
            self.add_auto_segment(
                0, len(self.raw), 0, len(self.raw),
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

            # Create code section
            self.add_auto_section('.text', 0, len(self.raw),
                                  SectionSemantics.ReadOnlyCodeSectionSemantics)

            # Setup the entry point
            self.add_entry_point(0)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, 0, '_start'))

            return True
        except Exception:
            log.log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0

    def perform_get_address_size(self):
        return Brainfuck.address_size


Brainfuck.register()
BrainfuckView.register()
