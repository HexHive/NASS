import ghidra.program.model.pcode
import java.lang


class VarnodeData(object):
    """
    All the resolved pieces of data needed to build a Varnode
    """

    offset: long
    size: int
    space: ghidra.program.model.address.AddressSpace



    def __init__(self): ...



    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode the data to stream as an \<addr> element
        @param encoder is the stream encoder
        @throws IOException for errors writing to the underlying stream
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

