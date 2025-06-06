from typing import List
import ghidra.app.util.bin
import ghidra.file.formats.dump
import ghidra.file.formats.dump.mdmp
import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.util.task
import java.lang
import java.util


class Minidump(ghidra.file.formats.dump.DumpFile):
    SIGNATURE: int = 1347241037



    def __init__(self, __a0: ghidra.file.formats.dump.DumpFileReader, __a1: ghidra.program.model.data.ProgramBasedDataTypeManager, __a2: List[object], __a3: ghidra.util.task.TaskMonitor): ...



    def addExteriorAddressObject(self, __a0: unicode, __a1: long, __a2: long, __a3: long) -> None: ...

    def addInteriorAddressObject(self, __a0: unicode, __a1: long, __a2: long, __a3: long) -> None: ...

    def analyze(self, __a0: ghidra.util.task.TaskMonitor) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self, __a0: long) -> ghidra.program.model.address.Address: ...

    def getClass(self) -> java.lang.Class: ...

    def getContextOffset(self) -> long: ...

    def getData(self) -> List[object]: ...

    @staticmethod
    def getDefaultOptions(__a0: ghidra.file.formats.dump.DumpFileReader) -> java.util.Collection: ...

    def getDirectories(self) -> List[ghidra.file.formats.dump.mdmp.Directory]: ...

    def getExteriorAddressRanges(self) -> java.util.Map: ...

    def getFileBytes(self, __a0: ghidra.util.task.TaskMonitor) -> ghidra.program.database.mem.FileBytes: ...

    def getFileHeader(self) -> ghidra.file.formats.dump.mdmp.MdmpFileHeader: ...

    def getInteriorAddressRanges(self) -> java.util.Map: ...

    @staticmethod
    def getMachineType(__a0: ghidra.file.formats.dump.DumpFileReader) -> unicode: ...

    def getModules(self) -> List[object]: ...

    def getProcessId(self) -> unicode: ...

    def getProcesses(self) -> List[object]: ...

    def getStreamByDir(self, __a0: int) -> ghidra.app.util.bin.StructConverter: ...

    def getStreamByType(self, __a0: int) -> ghidra.app.util.bin.StructConverter: ...

    def getThreadId(self) -> unicode: ...

    def getThreads(self) -> List[object]: ...

    def getTypeFromArchive(self, __a0: ghidra.program.model.data.CategoryPath, __a1: unicode) -> ghidra.program.model.data.DataType: ...

    def hashCode(self) -> int: ...

    def joinBlocksEnabled(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def directories(self) -> List[ghidra.file.formats.dump.mdmp.Directory]: ...

    @property
    def fileHeader(self) -> ghidra.file.formats.dump.mdmp.MdmpFileHeader: ...