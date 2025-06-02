import ghidra.app.util.importer
import ghidra.file.formats.android.oat
import ghidra.file.formats.android.oat.bundle
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class OatBundleFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getOatBundle(__a0: ghidra.program.model.listing.Program, __a1: ghidra.file.formats.android.oat.OatHeader, __a2: ghidra.util.task.TaskMonitor, __a3: ghidra.app.util.importer.MessageLog) -> ghidra.file.formats.android.oat.bundle.OatBundle: ...

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

