from typing import List
import ghidra.app.plugin.core.debug.gui.colors
import java.lang


class SelectionGenerator(object):








    def addSelections(self, __a0: long, __a1: ghidra.app.plugin.core.debug.gui.colors.SelectionTranslator, __a2: List[object]) -> None: ...

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

