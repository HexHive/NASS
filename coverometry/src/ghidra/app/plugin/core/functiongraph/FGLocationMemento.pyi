from typing import List
import ghidra.app.nav
import ghidra.framework.options
import ghidra.program.model.listing
import ghidra.program.util
import java.lang


class FGLocationMemento(ghidra.app.nav.LocationMemento):




    def __init__(self, __a0: ghidra.framework.options.SaveState, __a1: List[ghidra.program.model.listing.Program]): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLocationDescription(self) -> unicode: ...

    @staticmethod
    def getLocationMemento(__a0: ghidra.framework.options.SaveState, __a1: List[ghidra.program.model.listing.Program]) -> ghidra.app.nav.LocationMemento: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation: ...

    def hashCode(self) -> int: ...

    def isValid(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def saveState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

