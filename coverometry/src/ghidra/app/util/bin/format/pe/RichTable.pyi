from typing import List
import ghidra.app.util.bin.format.pe.rich
import ghidra.program.model.data
import java.lang


class RichTable(object):
    """
    Top level object model of the RichHeader.  Stores an array of
     RichHeaderRecord.
    """





    @overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader): ...

    @overload
    def __init__(self, buf: ghidra.program.model.mem.MemBuffer): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMask(self) -> int: ...

    def getOffset(self) -> long: ...

    def getRecords(self) -> List[ghidra.app.util.bin.format.pe.rich.RichHeaderRecord]: ...

    def getSize(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def mask(self) -> int: ...

    @property
    def offset(self) -> long: ...

    @property
    def records(self) -> List[ghidra.app.util.bin.format.pe.rich.RichHeaderRecord]: ...

    @property
    def size(self) -> int: ...