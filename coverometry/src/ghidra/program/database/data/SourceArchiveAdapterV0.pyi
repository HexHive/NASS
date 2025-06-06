import ghidra.program.database.data
import java.lang


class SourceArchiveAdapterV0(ghidra.program.database.data.SourceArchiveAdapter):
    """
    Version 0 implementation for accessing the Data Type Archive ID database table. 
 
     NOTE: Use of tablePrefix introduced with this adapter version.
    """





    def __init__(self): ...



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

