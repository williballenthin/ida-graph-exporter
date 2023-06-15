import json
import pathlib
import logging
import binascii
import dataclasses
from typing import List
from dataclasses import dataclass

import ida_gdl
import ida_name
import ida_bytes
import ida_lines
import ida_funcs
import ida_graph
import ida_idaapi
import ida_kernwin
import idautils

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


###############################################################################
#### begin: idapython_lex_curline
# via: https://gist.github.com/williballenthin/466eb28679d30e212ffac57e4a9ceaa5
# note: inline here for simplicity
# updates:
#   - use dataclasses instead of custom classes.
#   - resolve color name during lexing, not during rendering.
#   - parse addresses into their own symbols

# inverse mapping of color value to name.
# ref: https://www.hex-rays.com/products/ida/support/sdkdoc/group___s_c_o_l_o_r__.html#ga6052470f86411b8b5ffdf4af4bbee225
INV_COLORS = {
    0x1: 'COLOR_DEFAULT',  #= 0x01,         // Default
    0x2: 'COLOR_REGCMT',   #= 0x02,         // Regular comment
    0x3: 'COLOR_RPTCMT',   #= 0x03,         // Repeatable comment (comment defined somewhere else)
    0x4: 'COLOR_AUTOCMT',  #= 0x04,         // Automatic comment
    0x5: 'COLOR_INSN',     #= 0x05,         // Instruction
    0x6: 'COLOR_DATNAME',  #= 0x06,         // Dummy Data Name
    0x7: 'COLOR_DNAME',    #= 0x07,         // Regular Data Name
    0x8: 'COLOR_DEMNAME',  #= 0x08,         // Demangled Name
    0x9: 'COLOR_SYMBOL',   #= 0x09,         // Punctuation
    0xa: 'COLOR_CHAR',     #= 0x0A,         // Char constant in instruction
    0xb: 'COLOR_STRING',   #= 0x0B,         // String constant in instruction
    0xc: 'COLOR_NUMBER',   #= 0x0C,         // Numeric constant in instruction
    0xd: 'COLOR_VOIDOP',   #= 0x0D,         // Void operand
    0xe: 'COLOR_CREF',     #= 0x0E,         // Code reference
    0xf: 'COLOR_DREF',     #= 0x0F,         // Data reference
    0x10: 'COLOR_CREFTAIL', #= 0x10,         // Code reference to tail byte
    0x11: 'COLOR_DREFTAIL', #= 0x11,         // Data reference to tail byte
    0x12: 'COLOR_ERROR',    #= 0x12,         // Error or problem
    0x13: 'COLOR_PREFIX',   #= 0x13,         // Line prefix
    0x14: 'COLOR_BINPREF',  #= 0x14,         // Binary line prefix bytes
    0x15: 'COLOR_EXTRA',    #= 0x15,         // Extra line
    0x16: 'COLOR_ALTOP',    #= 0x16,         // Alternative operand
    0x17: 'COLOR_HIDNAME',  #= 0x17,         // Hidden name
    0x18: 'COLOR_LIBNAME',  #= 0x18,         // Library function name
    0x19: 'COLOR_LOCNAME',  #= 0x19,         // Local variable name
    0x1A: 'COLOR_CODNAME',  #= 0x1A,         // Dummy code name
    0x1B: 'COLOR_ASMDIR',   #= 0x1B,         // Assembler directive
    0x1C: 'COLOR_MACRO',    #= 0x1C,         // Macro
    0x1D: 'COLOR_DSTR',     #= 0x1D,         // String constant in data directive
    0x1E: 'COLOR_DCHAR',    #= 0x1E,         // Char constant in data directive
    0x1F: 'COLOR_DNUM',     #= 0x1F,         // Numeric constant in data directive
    0x20: 'COLOR_KEYWORD',  #= 0x20,         // Keywords
    0x21: 'COLOR_REG',      #= 0x21,         // Register name
    0x22: 'COLOR_IMPNAME',  #= 0x22,         // Imported name
    0x23: 'COLOR_SEGNAME',  #= 0x23,         // Segment name
    0x24: 'COLOR_UNKNAME',  #= 0x24,         // Dummy unknown name
    0x25: 'COLOR_CNAME',    #= 0x25,         // Regular code name
    0x26: 'COLOR_UNAME',    #= 0x26,         // Regular unknown name
    0x27: 'COLOR_COLLAPSED',#= 0x27,         // Collapsed line

    #  // Fictive colors
    0x28: 'COLOR_ADDR',     #= 0x28, // hidden address marks
                            #        // The address is represented as 8digit
                            #        // hex number: 01234567
                            #        // It doesn't have COLOR_OFF pair
                            #        // NB: for 64-bit IDA, the address is 16digit

    0x29: 'COLOR_OPND1',    #= COLOR_ADDR+1, // Instruction operand 1
    0x2A: 'COLOR_OPND2',    #= COLOR_ADDR+2, // Instruction operand 2
    0x2B: 'COLOR_OPND3',    #= COLOR_ADDR+3, // Instruction operand 3
    0x2C: 'COLOR_OPND4',    #= COLOR_ADDR+4, // Instruction operand 4
    0x2D: 'COLOR_OPND5',    #= COLOR_ADDR+5, // Instruction operand 5
    0x2E: 'COLOR_OPND6',    #= COLOR_ADDR+6, // Instruction operand 6
    0x2F: 'COLOR_OPND7',    #= COLOR_ADDR+7, // Instruction operand 7
    0x30: 'COLOR_OPND8',    #= COLOR_ADDR+8, // Instruction operand 8

    0x32: 'COLOR_UTF8',     #= COLOR_ADDR+10;// Following text is UTF-8 encoded
    0x33: 'RESERVED1',      #= COLOR_ADDR+11;// This tag is reserved for internal IDA use.
    0x34: 'LUMINA',         #= COLOR_ADDR+12;// Lumina-related, only for the navigation band.
}

# 000000	 //
# f2f8f8	 //Default color
# a47262	 //Regular comment
# a47262	 //Repeatable comment
# a47262	 //Automatic comment
# 6cb8ff	 //Instruction
# fde98b	 //Dummy Data Name
# fde98b	 //Regular Data Name
# fde98b	 //Demangled Name
# fde98b	 //Punctuation
# 7bfa50	 //Char constant in instruction
# 7bfa50	 //String constant in instruction
# 7bfa50	 //Numeric constant in instruction
# 6cb8ff	 //Void operand
# 7bfa50	 //Code reference
# f993bd	 //Data reference
# 5555ff	 //Code reference to tail byte
# 8cfaf1	 //Data reference to tail byte
# 5555ff	 //Error or problem
# c0c0c0	 //Line prefix
# fde98b	 //Binary line prefix bytes
# a47262	 //Extra line
# fde98b	 //Alternative operand
# a47262	 //Hidden name
# ff8080	 //Library function name
# 7bfa50	 //Local variable name
# fde98b	 //Dummy code name
# fde98b	 //Assembler directive
# f993bd	 //Macro
# 7bfa50	 //String constant in data directive
# 7bfa50	 //Char constant in data directive
# 7bfa50	 //Numeric constant in data directive
# fde98b	 //Keywords
# fde98b	 //Register name
# c679ff	 //Imported name
# 8cfaf1	 //Segment name
# fde98b	 //Dummy unknown name
# fde98b	 //Regular code name
# fde98b	 //Regular unknown name
# a47262	 //Collapsed line
# 000000	 //Max color number
# 362a28	 //Line prefix: library function
# afbbc0	 //Line prefix: regular function
# fde98b	 //Line prefix: instruction
# a47262	 //Line prefix: data
# 5555ff	 //Line prefix: unexplored
# a47262	 //Line prefix: externs
# 8cfaf1	 //Line prefix: current item
# c679ff	 //Line prefix: current line
# 5a4744	 //Punctuation
# 5a4744	 //Opcode bytes
# 000000	 //Manual operand
# 7bfa50	 //Error


@dataclass
class StringSymbol:
    string: str
    type: str = 'string'

    def __str__(self):
        return 'STRING=' + self.string


@dataclass
class AddressSymbol:
    address: int
    type: str = 'address'

    def __str__(self):
        return 'ADDRESS=' + hex(self.address)


@dataclass
class ColorOnSymbol:
    color: str
    type: str = 'coloron'

    def __str__(self):
        return 'COLORON=' + self.color 


@dataclass
class ColorOffSymbol:
    color: str
    type: str = 'coloroff'

    def __str__(self):
        return 'COLOROFF=' + self.color


@dataclass
class ColorInvSymbol:
    type: str = 'colorinv'

    def __str__(self):
        return 'COLORINV'


def lex(curline):
    '''
    split the line returned by `get_custom_viewer_curline` into symbols.
    it pulls out the strings, color directives, and escaped characters.
    
    Args:
      curline (str): a line returned by `ida_kernwin.get_custom_viewer_curline`
    
    Returns:
      generator: generator of Symbol subclass instances
    '''
    offset = 0
    cur_word = []
    while offset < len(curline):

        c = curline[offset]

        if c == ida_lines.COLOR_ON:
            if cur_word:
                yield StringSymbol(''.join(cur_word))
                cur_word = []

            offset += 1
            color = curline[offset]

            offset += 1

            if INV_COLORS[ord(color)] == "COLOR_ADDR":
                # assume we're in ida64!
                # next 16 characters are hex-encoded number
                # like: 0000000000470670
                size = 0x10
                address = int(curline[offset:offset+size], 0x10)
                offset += size
                yield AddressSymbol(address)
            else:
                yield ColorOnSymbol(INV_COLORS[ord(color)])

        elif c == ida_lines.COLOR_OFF:
            if cur_word:
                yield StringSymbol(''.join(cur_word))
                cur_word = []

            offset += 1
            color = curline[offset]

            yield ColorOffSymbol(INV_COLORS[ord(color)])
            offset += 1

        elif c == ida_lines.COLOR_ESC:
            if cur_word:
                yield StringSymbol(''.join(cur_word))
                cur_word = []

            offset += 1
            c = curline[offset]

            cur_word.append(c)
            offset += 1

        elif c == ida_lines.COLOR_INV:
            if cur_word:
                yield StringSymbol(''.join(cur_word))
                cur_word = []

            yield ColorInvSymbol()
            offset += 1

        else:
            cur_word.append(c)
            offset += 1


def get_color_at_char(curline, index):
    curlen = 0
    curcolor = 0
    for sym in lex(curline):
        if sym.type == 'string':
            curlen += len(sym.string)
            if curlen >= index:
                return curcolor
        elif sym.type == 'coloron':
            curcolor = sym.color
        elif sym.type == 'coloroff':
            curcolor = 0
        else:
            curcolor = 0

    return curcolor


def get_token_at_char(curline, index):
    curlen = 0
    curcolor = 0
    for sym in lex(curline):
        if sym.type == 'string':
            curlen += len(sym.string)
            if curlen >= index:
                return sym.string
        else:
            continue

    return ''


#### end: idapython_lex_curline
###############################################################################


@dataclass
class Rectangle:
    left: int
    right: int
    top: int
    bottom: int


@dataclass
class Range:
    start: int
    length: int

    @property
    def end(self):
        return self.start + self.length


@dataclass
class DisassemblyLine:
    tokens: List[str]
    bg_color: int
    prefix_color: int
    is_default: bool


@dataclass
class Location:
    address: int
    lines: List[DisassemblyLine]
    name: str | None = None


@dataclass
class BasicBlock:
    rect: Rectangle
    range: Range
    bytes: str  # hex-encoded bytes
    locations: List[Location]


@dataclass
class Point:
    x: int
    y: int


@dataclass
class Edge:
    color: int
    points: List[Point]


@dataclass
class Graph:
    basic_blocks: List[BasicBlock]
    edges: List[Edge]


def export_locations(start, end):
    locations = []

    for head in idautils.Heads(start, end):
        disassembly: ida_kernwin.disasm_text_t = ida_kernwin.disasm_text_t()
        ida_kernwin.gen_disasm_text(disassembly, head, head + 1, False)

        lines = [
            DisassemblyLine(
                tokens=list(lex(line.line)),
                bg_color=line.bg_color,
                prefix_color=line.prefix_color,
                is_default=line.is_default,
            ) for line in disassembly
        ]

        name = ida_name.get_name(head)

        locations.append(Location(
            address=head,
            lines=lines,
            name=name,
        ))

    return locations


def export_current_graph():
    va = ida_kernwin.get_screen_ea()
    f = ida_funcs.get_func(va)

    if not f:
        raise ValueError("function not found: 0x%x" % va)

    # FC_NOEXT: don't show edges to external blocks, such as via direct jumps
    flowchart = ida_gdl.FlowChart(f, flags=ida_gdl.FC_NOEXT)
    if not flowchart or flowchart.size == 0:
        raise ValueError("flowchart is empty")

    gv: ida_kernwin.graph_viewer_t = ida_kernwin.get_current_viewer()
    g: ida_graph.mutable_graph_t = ida_graph.get_viewer_graph(gv)

    # while its possible to use ida_graph.create_disasm_graph(va)
    # for arbitrary va
    # it doesn't have an associated rendering context
    # so the resulting offsets/points/rects don't make sense.

    graph: Graph = Graph(basic_blocks=[], edges=[])

    for i in range(flowchart.size):
        # is the order guaranteed to be the same here?
        rect: ida_graph.rect_t = g.nodes[i]
        basic_block: ida_gdl.BasicBlock = flowchart[i]

        disassembly: ida_kernwin.disasm_text_t = ida_kernwin.disasm_text_t()
        ida_kernwin.gen_disasm_text(disassembly, basic_block.start_ea, basic_block.end_ea, False)

        graph.basic_blocks.append(BasicBlock(
            rect=Rectangle(
                left=rect.left,
                right=rect.right,
                top=rect.top,
                bottom=rect.bottom,
            ),
            range=Range(
                start=basic_block.start_ea,
                length=basic_block.end_ea - basic_block.start_ea,
            ),
            bytes=binascii.hexlify(ida_bytes.get_bytes(
                basic_block.start_ea,
                basic_block.end_ea - basic_block.start_ea)
            ).decode('ascii'),
            locations=export_locations(basic_block.start_ea, basic_block.end_ea),
        ))

        for succ in basic_block.succs():
            j = succ.id
            edge_spec = ida_graph.edge_t(i, j)
            edge = g.get_edge(edge_spec)

            if not edge:
                raise ValueError(f"edge not found: {i} -> {j}")

            points = []
            points.append(Point(rect.left + edge.srcoff, rect.bottom))

            for p in edge.layout:
                points.append(Point(p.x, p.y))

            dst_node: ida_graph.rect_t = g.nodes[j]
            points.append(Point(dst_node.left + edge.dstoff, dst_node.top))

            graph.edges.append(Edge(
                color=edge.color,
                points=points,
            ))

    return graph


class DataclassJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


def main():
    graph = export_current_graph()

    doc = json.dumps(graph, cls=DataclassJSONEncoder, indent=2, sort_keys=True)

    path = ida_kernwin.ask_file(True, "*", "json file to save graph")
    if not path:
        #print(doc)
        return

    pathlib.Path(path).write_text(doc, encoding="utf-8")


if __name__ == "__main__":
    main()