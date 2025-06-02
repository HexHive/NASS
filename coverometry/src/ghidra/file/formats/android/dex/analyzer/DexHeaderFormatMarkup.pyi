import ghidra.app.util.importer
import ghidra.util.task
import java.lang


class DexHeaderFormatMarkup(object):




    def __init__(self, __a0: ghidra.file.formats.android.dex.analyzer.DexHeaderFormatAnalyzer, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.address.Address): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markup(self, __a0: ghidra.util.task.TaskMonitor, __a1: ghidra.app.util.importer.MessageLog) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

