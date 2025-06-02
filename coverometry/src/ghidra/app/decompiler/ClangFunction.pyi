from typing import Iterator
from typing import List
import ghidra.app.decompiler
import ghidra.program.model.address
import ghidra.program.model.pcode
import java.awt
import java.lang
import java.util
import java.util.function
import java.util.stream


class ClangFunction(ghidra.app.decompiler.ClangTokenGroup):
    """
    A grouping of source code tokens representing an entire function
    """





    def __init__(self, parent: ghidra.app.decompiler.ClangNode, hfunc: ghidra.program.model.pcode.HighFunction): ...

    def __iter__(self): ...

    def AddTokenGroup(self, obj: ghidra.app.decompiler.ClangNode) -> None:
        """
        Add additional text to this group
        @param obj is the additional text
        """
        ...

    def Child(self, i: int) -> ghidra.app.decompiler.ClangNode: ...

    def Parent(self) -> ghidra.app.decompiler.ClangNode: ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, pfactory: ghidra.program.model.pcode.PcodeFactory) -> None:
        """
        Decode this text from an encoded stream.
        @param decoder is the decoder for the stream
        @param pfactory is used to look up p-code attributes to associate with tokens
        @throws DecoderException for problems decoding the stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def flatten(self, __a0: List[object]) -> None: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClangFunction(self) -> ghidra.app.decompiler.ClangFunction: ...

    def getClass(self) -> java.lang.Class: ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        """
        @return the HighFunction object represented by this source code
        """
        ...

    def getMaxAddress(self) -> ghidra.program.model.address.Address: ...

    def getMinAddress(self) -> ghidra.program.model.address.Address: ...

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
    def clangFunction(self) -> ghidra.app.decompiler.ClangFunction: ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction: ...