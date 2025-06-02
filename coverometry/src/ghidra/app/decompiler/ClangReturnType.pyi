from typing import Iterator
from typing import List
import ghidra.app.decompiler
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.pcode
import java.awt
import java.lang
import java.util
import java.util.function
import java.util.stream


class ClangReturnType(ghidra.app.decompiler.ClangTokenGroup):
    """
    A grouping of source code tokens representing the "return type" of a function,
     as at the beginning of a function prototype.
    """





    def __init__(self, par: ghidra.app.decompiler.ClangNode): ...

    def __iter__(self): ...

    def AddTokenGroup(self, obj: ghidra.app.decompiler.ClangNode) -> None:
        """
        Add additional text to this group
        @param obj is the additional text
        """
        ...

    def Child(self, i: int) -> ghidra.app.decompiler.ClangNode: ...

    def Parent(self) -> ghidra.app.decompiler.ClangNode: ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, pfactory: ghidra.program.model.pcode.PcodeFactory) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def flatten(self, __a0: List[object]) -> None: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClangFunction(self) -> ghidra.app.decompiler.ClangFunction: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        @return the data-type represented by this text
        """
        ...

    def getMaxAddress(self) -> ghidra.program.model.address.Address: ...

    def getMinAddress(self) -> ghidra.program.model.address.Address: ...

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        @return a Varnode representing the return value in the function's data-flow
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.app.decompiler.ClangNode]: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def numChildren(self) -> int: ...

    def setHighlight(self, val: java.awt.Color) -> None: ...

    def spliterator(self) -> java.util.Spliterator: ...

    def stream(self) -> java.util.stream.Stream:
        """
        Gets a stream over this group's children
        @return a stream of this group's children
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode: ...