import ghidra.program.util.string
import ghidra.util.task
import java.lang


class CombinedStringSearcher(object):




    def __init__(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.app.plugin.core.string.StringTableOptions, __a2: ghidra.util.datastruct.Accumulator): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def onlyShowWordStrings(self) -> bool: ...

    def search(self, __a0: ghidra.util.task.TaskMonitor) -> None: ...

    def shouldAddDefinedString(self, __a0: ghidra.program.util.string.FoundString) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

