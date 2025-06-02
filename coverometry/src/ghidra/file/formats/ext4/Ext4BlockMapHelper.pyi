from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import java.lang


class Ext4BlockMapHelper(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getByteProvider(__a0: List[int], __a1: ghidra.app.util.bin.ByteProvider, __a2: long, __a3: int, __a4: ghidra.formats.gfilesystem.FSRL) -> ghidra.app.util.bin.ByteProvider: ...

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

