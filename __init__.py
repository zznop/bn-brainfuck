"""
Binary Ninja plugin that models Brainfuck programs
"""

from binaryninja import *
import re
import traceback


def cond_branch(il, cond, addr_true, addr_false):
    """
    Creates a llil conditional branch expression
    """

    t = il.get_label_for_address(Architecture['Brainfuck'], addr_true)
    if t is None:
        t = LowLevelILLabel()
    f = il.get_label_for_address(Architecture['Brainfuck'], addr_false)
    if f is None:
        f = LowLevelILLabel()
    il.append(il.if_expr(cond, t, f))


class DefaultCallingConvention(CallingConvention):
    """
    Defines the default calling convention for stdout/stdin operations
    """

    name = 'default'
    int_arg_regs = ['cp']
    callee_saved_regs = ['cp']
    int_return_reg = 'ret'


class Brainfuck(Architecture):
    """
    This class is responsible for disassembling and lifting Brainfuck code
    """

    name = 'Brainfuck'
    address_size = 4
    default_int_size = 4
    instr_alignment = 1
    max_instr_length = 1
    regs = {
        'sp': function.RegisterInfo('sp', 4),  # Not used, but required
        'cp': function.RegisterInfo('cp', 4),  # Cell pointer
        'ret': function.RegisterInfo(
            'ret', 4),  # Not used, but needed for the calling convention
    }

    stack_pointer = 'sp'  # Not use, but required
    bracket_mem = {}

    def get_instruction_info(self, data, addr):
        """
        Unused. Basic block analysis is performed in analyze_basic_blocks.
        """

        info = function.InstructionInfo()
        info.length = 1
        return info

    def _addr_is_executable(self, data, addr):
        """
        Check if the address is in the code section
        """

        sections = data.get_sections_at(addr)
        return sections and sections[
            0].semantics == SectionSemantics.ReadOnlyCodeSectionSemantics

    def analyze_basic_blocks(self, func, context):
        """
        Custom implementation of basic block analysis
        """

        data = func.view
        blocks_to_process = [func.start]
        seen_blocks = []
        instr_blocks = {}
        loop_starts = []

        while len(blocks_to_process) > 0:
            if data.analysis_is_aborted:
                break

            curr_addr = blocks_to_process.pop()
            if not self._addr_is_executable(data, curr_addr):
                continue

            # Check if this block has already been proessed
            if curr_addr in seen_blocks:
                continue
            seen_blocks.append(curr_addr)

            # New block, process the instructions
            block = context.create_basic_block(func.arch, curr_addr)
            instr_blocks[curr_addr] = block
            ends_block = False
            while True:
                instr = data.read(curr_addr,
                                  1)  # Each BF instruction is 1 character

                # Handle loop instructions
                if instr == b'[':
                    # Start of loop, end the current block
                    loop_starts.append(curr_addr)
                    block.end = curr_addr

                    # Start a new block
                    block.add_pending_outgoing_edge(
                        BranchType.UnconditionalBranch, curr_addr, func.arch)
                    context.add_basic_block(block)
                    block = context.create_basic_block(func.arch, curr_addr)
                elif instr == b']':
                    # End of loop, find the nearest loop start in lower memory
                    target = None
                    loop_starts.sort(reverse=True)
                    for i in range(len(loop_starts)):
                        if loop_starts[i] < curr_addr:
                            target = loop_starts[i]
                            loop_starts.pop(i)
                            break

                    if target:
                        block.add_pending_outgoing_edge(BranchType.TrueBranch,
                                                        target, func.arch)
                    else:
                        log.log_warn(f'No matching [ for ] at {hex(curr_addr)}')

                    block.add_pending_outgoing_edge(BranchType.FalseBranch,
                                                    curr_addr + 1, func.arch)
                    blocks_to_process.append(curr_addr + 1)
                    ends_block = True

                # Add the instruction to the block
                block.add_instruction_data(instr)

                # Check if it's the last instruction in the program
                if curr_addr + 1 >= data.end:
                    ends_block = True

                curr_addr += 1
                if not self._addr_is_executable(data, curr_addr):
                    ends_block = True

                if ends_block:
                    break

            if curr_addr != block.start:
                block.end = curr_addr
                context.add_basic_block(block)

        context.finalize()

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
        elif c == '[':
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'loopstart'),
            ]
        elif c in ['\n', ' ']:
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'nop'),
            ]
        elif c == ']':
            tokens = [
                InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     'loopend'),
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

    def repeated_op_count(self, data, op):
        """
        Count repeated operations that can be used to simplify IL
        """

        count = 0
        for b in data:
            if b == op:
                count += 1
            else:
                break

        return count

    def get_instruction_low_level_il(self, data, addr, il):
        """
        Lift instructions to LLIL
        """

        if isinstance(data, bytes):
            data = data.decode()

        if addr == 0x800000:
            il.append(il.set_reg(4, 'cp', il.const(4, 0x1000000)))

        op = data[0]
        ilen = 1
        if op == '+':
            incval = self.repeated_op_count(data, '+')
            ilen = incval
            il.append(
                il.store(
                    1, il.reg(4, 'cp'),
                    il.add(1, il.load(1, il.reg(4, 'cp')), il.const(1,
                                                                    incval))))
        elif op == '-':
            decval = self.repeated_op_count(data, '-')
            ilen = decval
            il.append(
                il.store(
                    1, il.reg(4, 'cp'),
                    il.sub(1, il.load(1, il.reg(4, 'cp')), il.const(1,
                                                                    decval))))
        elif op == '>':
            incval = self.repeated_op_count(data, '>')
            ilen = incval
            il.append(
                il.set_reg(4, 'cp',
                           il.add(4, il.reg(4, 'cp'), il.const(1, incval))))
        elif op == '<':
            decval = self.repeated_op_count(data, '<')
            ilen = decval
            il.append(
                il.set_reg(4, 'cp',
                           il.sub(4, il.reg(4, 'cp'), il.const(1, decval))))
        elif op in ['[', ' ', '\n']:
            il.append(il.nop())
        elif op == ']':
            edges = il.source_function.get_basic_block_at(addr).outgoing_edges
            addr_true = None
            for edge in edges:
                if edge.type == BranchType.TrueBranch:
                    addr_true = edge.target.start

            if not addr_true:
                log.log_warn(f'No true branch found for ] at {hex(addr)}')
                return 1

            addr_false = addr + 1
            cond = il.compare_not_equal(1, il.load(1, il.reg(4, 'cp')),
                                        il.const(1, 0))
            cond_branch(il, cond, addr_true, addr_false)
        elif op == '.':
            il.append(il.call(il.const(4, 0x2000000)))
        elif op == ',':
            il.append(il.call(il.const(4, 0x2000001)))
        else:
            il.append(il.undefined())

        return ilen


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
            # Create code section
            self.add_auto_segment(
                0x800000, len(self.raw), 0, len(self.raw),
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_auto_section('.code', 0x800000, len(self.raw),
                                  SectionSemantics.ReadOnlyCodeSectionSemantics)

            # Create cells section
            self.add_auto_segment(
                0x1000000, 30000, 0, 0,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
            self.add_auto_section(
                '.cells', 0x1000000, 30000,
                SectionSemantics.ReadWriteDataSectionSemantics)
            self.define_data_var(0x1000000, 'uint8_t cells[30000]', 'cells')

            # Create extern section for stdout stdin "imports"
            self.add_auto_segment(0x2000000, 2, 0, 0,
                                  SegmentFlag.SegmentReadable)
            self.add_auto_section('.extern', 0x2000000, 2,
                                  SectionSemantics.ExternalSectionSemantics)

            # Define the symbols for stdout and stdin
            self.define_auto_symbol(
                Symbol(SymbolType.SymbolicFunctionSymbol, 0x2000000, 'stdout'))
            self.define_data_var(0x2000000, 'void stdout(char *c)')
            self.define_auto_symbol(
                Symbol(SymbolType.SymbolicFunctionSymbol, 0x2000001, 'stdin'))
            self.define_data_var(0x2000001, 'void stdin(char *c)')

            # Setup the entry point
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, 0x800000, '_start'))
            self.add_entry_point(0x800000)

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
arch = Architecture['Brainfuck']
arch.register_calling_convention(DefaultCallingConvention(arch, 'default'))
arch.standalone_platform.default_calling_convention = arch.calling_conventions[
    'default']
BrainfuckView.register()
