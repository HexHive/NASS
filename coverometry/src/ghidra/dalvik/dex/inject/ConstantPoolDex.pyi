from typing import List
import ghidra.program.model.lang
import java.lang


class ConstantPoolDex(ghidra.program.model.lang.ConstantPool):




    def __init__(self, __a0: ghidra.program.model.listing.Program): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getRecord(self, __a0: List[long]) -> ghidra.program.model.lang.ConstantPool.Record: ...

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

