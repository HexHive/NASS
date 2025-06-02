import ghidra.app.plugin.processors.sleigh
import ghidra.program.model.address
import ghidra.xml
import java.lang


class HandleTpl(object):
    """
    Placeholder that resolves for a specific InstructionContext into a FixedHandle
     representing the semantic value of a Constructor
    """





    def __init__(self, spc: ghidra.app.plugin.processors.sleigh.template.ConstTpl, sz: ghidra.app.plugin.processors.sleigh.template.ConstTpl, ptrspc: ghidra.app.plugin.processors.sleigh.template.ConstTpl, ptroff: ghidra.app.plugin.processors.sleigh.template.ConstTpl, ptrsz: ghidra.app.plugin.processors.sleigh.template.ConstTpl, tmpspc: ghidra.app.plugin.processors.sleigh.template.ConstTpl, tmpoff: ghidra.app.plugin.processors.sleigh.template.ConstTpl): ...



    def equals(self, __a0: object) -> bool: ...

    def fix(self, hand: ghidra.app.plugin.processors.sleigh.FixedHandle, walker: ghidra.app.plugin.processors.sleigh.ParserWalker) -> None: ...

    def fixPrintPiece(self, hand: ghidra.app.plugin.processors.sleigh.FixedHandle, walker: ghidra.app.plugin.processors.sleigh.ParserWalker, handleIndex: int) -> None: ...

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the address space of the value, if applicable
        @return the address space, or null if not applicable
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getOffsetOperandIndex(self) -> int: ...

    def getSize(self) -> int:
        """
        Get the size of the expected value in bits
        @return the number of bits
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, factory: ghidra.program.model.address.AddressFactory) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def offsetOperandIndex(self) -> int: ...

    @property
    def size(self) -> int: ...