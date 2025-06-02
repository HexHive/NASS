import ghidra.program.database.data
import java.lang


class CallingConventionDBAdapterNoTable(ghidra.program.database.data.CallingConventionDBAdapter):
    """
    Adapter when no Calling Convention table exists.
    """





    def __init__(self):
        """
        Gets a no-table adapter for the calling convention database table.
        """
        ...



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

