import ghidra.program.database.data
import java.lang


class SettingsDBAdapterV1(ghidra.program.database.data.SettingsDBAdapter):
    """
    Version 1 implementation for the accessing the data type settings database table.
     This version stores settings name as an index in each record which corresponds 
     to an entry in the into a second table for
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

