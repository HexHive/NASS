import ghidra.program.database.mem
import java.lang


class MemoryMapDBAdapterV3(ghidra.program.database.mem.MemoryMapDBAdapter):
    """
    MemoryMap adapter for version 3.
     This version introduces the concept of sub memory blocks and FileBytes
    """





    def __init__(self, handle: db.DBHandle, memMap: ghidra.program.database.mem.MemoryMapDB, maxSubBlockSize: long, create: bool): ...



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

