from typing import List
import ghidra.file.formats.android.art
import ghidra.util.task
import java.lang


class Decompressor(object):




    def __init__(self): ...



    @staticmethod
    def decompress(__a0: ghidra.file.formats.android.art.ArtStorageMode, __a1: List[int], __a2: int, __a3: ghidra.util.task.TaskMonitor) -> List[int]: ...

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

