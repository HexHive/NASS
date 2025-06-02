import java.lang


class DwarfCallFrameOpcodeParser(object):
    """
    An opcode parser for operands of a call frame instruction. 
     The operands are encoded as DWARF expressions.
 
     The data encodings can be found in the DWARF Debugging Information Format specification
     under Call Frame Information in the Data Representation section.
    """





    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, length: int):
        """
        Constructs an opcode parser.
        @param program the program with the bytes to parse
        @param address the address of the bytes to parse
        @param length the number of bytes to parse
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

