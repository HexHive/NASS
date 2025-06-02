from typing import List
import ghidra.program.model.address
import java.lang


class MemoryFaultHandler(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def uninitializedRead(self, __a0: ghidra.program.model.address.Address, __a1: int, __a2: List[int], __a3: int) -> bool: ...

    def unknownAddress(self, __a0: ghidra.program.model.address.Address, __a1: bool) -> bool: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

