import ghidra.program.database.symbol
import java.lang


class SymbolDatabaseAdapterV3(ghidra.program.database.symbol.SymbolDatabaseAdapter):
    """
    SymbolDatabaseAdapter for version 3
 
     This version provides for fast symbol lookup by namespace and name.
     It was created in June 2021 with ProgramDB version 24. 
     It will be included in Ghidra starting at version 10.1
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

