from typing import List
import ghidra.app.util.bin
import ghidra.file.formats.android.art
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class DecompressionManager(object):




    def __init__(self): ...



    @overload
    @staticmethod
    def decompress(__a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.file.formats.android.art.ArtCompression, __a2: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.BinaryReader: ...

    @overload
    @staticmethod
    def decompress(__a0: ghidra.app.util.bin.BinaryReader, __a1: List[object], __a2: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.BinaryReader: ...

    @overload
    @staticmethod
    def decompressOverMemory(__a0: ghidra.program.model.listing.Program, __a1: ghidra.file.formats.android.art.ArtCompression, __a2: ghidra.util.task.TaskMonitor) -> None: ...

    @overload
    @staticmethod
    def decompressOverMemory(__a0: ghidra.program.model.listing.Program, __a1: List[object], __a2: ghidra.util.task.TaskMonitor) -> None: ...

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

