from typing import List
import ghidra.app.util.bin
import ghidra.file.formats.java
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.factory
import ghidra.util.task
import java.lang


class JavaClassDecompilerFileSystemFactory(object, ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider, ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly):
    MAX_BYTESREQUIRED: int = 65536



    def __init__(self): ...



    def create(self, __a0: ghidra.formats.gfilesystem.FSRLRoot, __a1: ghidra.app.util.bin.ByteProvider, __a2: ghidra.formats.gfilesystem.FileSystemService, __a3: ghidra.util.task.TaskMonitor) -> ghidra.file.formats.java.JavaClassDecompilerFileSystem: ...

    def equals(self, __a0: object) -> bool: ...

    def getBytesRequired(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def probeStartBytes(self, __a0: ghidra.formats.gfilesystem.FSRL, __a1: List[int]) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def bytesRequired(self) -> int: ...