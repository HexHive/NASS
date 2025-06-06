import ghidra.program.model.address
import ghidra.program.model.pcode
import java.lang


class BlockMap(object):




    @overload
    def __init__(self, fac: ghidra.program.model.address.AddressFactory): ...

    @overload
    def __init__(self, op2: ghidra.program.model.pcode.BlockMap): ...



    def addGotoRef(self, gblock: ghidra.program.model.pcode.PcodeBlock, root: int, depth: int) -> None: ...

    def createBlock(self, name: unicode, index: int) -> ghidra.program.model.pcode.PcodeBlock: ...

    def equals(self, __a0: object) -> bool: ...

    def findLevelBlock(self, ind: int) -> ghidra.program.model.pcode.PcodeBlock:
        """
        Assume blocks are in index order, find the block with index -ind-
        @param ind is the block index to match
        @return the matching PcodeBlock
        """
        ...

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def resolveGotoReferences(self) -> None: ...

    def sortLevelList(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory: ...