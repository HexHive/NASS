from typing import List
import ghidra.file.formats.dump
import ghidra.file.formats.dump.pagedump
import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.util.task
import java.lang
import java.util


class Pagedump(ghidra.file.formats.dump.DumpFile):
    DEBUG_DATA_PATH_OPTION_DEFAULT: unicode = u''
    DEBUG_DATA_PATH_OPTION_NAME: unicode = u'Debug Data Path (e.g. /path/to/ntoskrnl.pdb)'
    DUMP_TYPE_AUTOMATIC: int = 7
    DUMP_TYPE_BITMAP_FULL: int = 5
    DUMP_TYPE_BITMAP_KERNEL: int = 6
    DUMP_TYPE_FULL: int = 1
    DUMP_TYPE_HEADER: int = 3
    DUMP_TYPE_SUMMARY: int = 2
    DUMP_TYPE_TRIAGE: int = 4
    DUMP_TYPE_UNKNOWN: int = 0
    ETHREAD_PID_OFFSET: long
    ETHREAD_TID_OFFSET: long
    MACHINE_TYPE_OFFSET32: int = 32
    MACHINE_TYPE_OFFSET64: int = 48
    OFFSET_HEADER: int = 0
    OFFSET_TRIAGE: int = 4096
    PAGE_SIZE: int = 4096
    SIGNATURE: int = 1162297680
    SIG_FULL: int = 1347241030
    SIG_SUMMARY: int = 1347241043
    SIG_VALID1: int = 1347245124
    SIG_VALID2: int = 1347245124
    TRIAGE_DUMP_BASIC_INFO: int = 255
    TRIAGE_DUMP_BROKEN_DRIVER: int = 128
    TRIAGE_DUMP_CONTEXT: int = 1
    TRIAGE_DUMP_DATAPAGE: int = 512
    TRIAGE_DUMP_DATA_BLOCKS: int = 2048
    TRIAGE_DUMP_DEBUGGER_DATA: int = 1024
    TRIAGE_DUMP_DRIVER_LIST: int = 64
    TRIAGE_DUMP_EXCEPTION: int = 2
    TRIAGE_DUMP_MMINFO: int = 256
    TRIAGE_DUMP_PRCB: int = 4
    TRIAGE_DUMP_PROCESS: int = 8
    TRIAGE_DUMP_STACK: int = 32
    TRIAGE_DUMP_THREAD: int = 16



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

    def getExteriorAddressRanges(self) -> java.util.Map: ...

    def getFileBytes(self, __a0: ghidra.util.task.TaskMonitor) -> ghidra.program.database.mem.FileBytes: ...

    def getFileHeader(self) -> ghidra.file.formats.dump.pagedump.PagedumpFileHeader: ...

    def getInteriorAddressRanges(self) -> java.util.Map: ...

    @staticmethod
    def getMachineType(__a0: ghidra.file.formats.dump.DumpFileReader) -> unicode: ...

    def getModules(self) -> List[object]: ...

    def getProcessId(self) -> unicode: ...

    def getProcesses(self) -> List[object]: ...

    def getThreadId(self) -> unicode: ...

    def getThreads(self) -> List[object]: ...

    def getTriageDump(self) -> ghidra.file.formats.dump.pagedump.TriageDump: ...

    def getTypeFromArchive(self, __a0: ghidra.program.model.data.CategoryPath, __a1: unicode) -> ghidra.program.model.data.DataType: ...

    def hashCode(self) -> int: ...

    def joinBlocksEnabled(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def usesPreloadedLists(self) -> bool: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def fileHeader(self) -> ghidra.file.formats.dump.pagedump.PagedumpFileHeader: ...

    @property
    def triageDump(self) -> ghidra.file.formats.dump.pagedump.TriageDump: ...