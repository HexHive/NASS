import ghidra.app.util.bin
import ghidra.app.util.importer
import ghidra.file.formats.android.oat
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class OatHeaderFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def newOatHeader(__a0: ghidra.app.util.bin.BinaryReader) -> ghidra.file.formats.android.oat.OatHeader: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def parseOatHeader(__a0: ghidra.file.formats.android.oat.OatHeader, __a1: ghidra.program.model.listing.Program, __a2: ghidra.app.util.bin.BinaryReader, __a3: ghidra.util.task.TaskMonitor, __a4: ghidra.app.util.importer.MessageLog) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

