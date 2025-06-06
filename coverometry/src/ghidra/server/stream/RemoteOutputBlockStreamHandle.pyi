import db.buffers
import ghidra.server.stream
import java.lang


class RemoteOutputBlockStreamHandle(ghidra.server.stream.RemoteBlockStreamHandle, db.buffers.BlockStreamHandle):
    serialVersionUID: long = 0x1L



    def __init__(self, __a0: ghidra.server.stream.BlockStreamServer, __a1: int, __a2: int): ...



    def equals(self, __a0: object) -> bool: ...

    def getBlockCount(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isPending(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openBlockStream(self) -> db.buffers.BlockStream: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

