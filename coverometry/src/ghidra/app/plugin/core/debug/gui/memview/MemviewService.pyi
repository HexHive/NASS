from typing import List
import ghidra.app.plugin.core.debug.gui.memview
import ghidra.program.model.listing
import java.lang


class MemviewService(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getProvider(self) -> ghidra.app.plugin.core.debug.gui.memview.MemviewProvider: ...

    def hashCode(self) -> int: ...

    def initViews(self) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setBoxes(self, __a0: List[object]) -> None: ...

    def setProgram(self, __a0: ghidra.program.model.listing.Program) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def boxes(self) -> None: ...  # No getter available.

    @boxes.setter
    def boxes(self, value: List[object]) -> None: ...

    @property
    def program(self) -> None: ...  # No getter available.

    @program.setter
    def program(self, value: ghidra.program.model.listing.Program) -> None: ...

    @property
    def provider(self) -> ghidra.app.plugin.core.debug.gui.memview.MemviewProvider: ...