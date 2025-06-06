import ghidra.file.formats.bplist
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class NSArray(ghidra.file.formats.bplist.NSObject):




    def __init__(self, __a0: int): ...



    def add(self, __a0: int) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getType(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def markup(self, __a0: ghidra.program.model.listing.Data, __a1: ghidra.program.model.listing.Program, __a2: ghidra.util.task.TaskMonitor) -> None: ...

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
    def type(self) -> unicode: ...