import ghidra.program.model.address
import java.lang
import java.nio


class ByteCache(object):
    BITS: int = 12
    OFFSET_MASK: long = -0x1000L
    SIZE: int = 4096



    def __init__(self, __a0: int): ...



    def canCache(self, __a0: ghidra.program.model.address.Address, __a1: int) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def invalidate(self, __a0: ghidra.program.model.address.AddressRange) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def read(self, __a0: ghidra.program.model.address.Address) -> int: ...

    @overload
    def read(self, __a0: ghidra.program.model.address.Address, __a1: java.nio.ByteBuffer) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

