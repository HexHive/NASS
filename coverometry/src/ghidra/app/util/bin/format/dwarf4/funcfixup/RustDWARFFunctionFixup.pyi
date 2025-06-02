from typing import List
import ghidra.app.util.bin.format.dwarf4.funcfixup
import ghidra.app.util.bin.format.dwarf4.next
import ghidra.program.model.listing
import java.lang


class RustDWARFFunctionFixup(object, ghidra.app.util.bin.format.dwarf4.funcfixup.DWARFFunctionFixup):
    """
    Prevent functions in a Rust compile unit from incorrectly being locked down to an empty signature.
    """

    PRIORITY_LAST: int = 1000
    PRIORITY_NORMAL: int = 3000
    PRIORITY_NORMAL_EARLY: int = 4000
    PRIORITY_NORMAL_LATE: int = 2000



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findFixups() -> List[object]: ...

    def fixupDWARFFunction(self, dfunc: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction, gfunc: ghidra.program.model.listing.Function) -> None: ...

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

