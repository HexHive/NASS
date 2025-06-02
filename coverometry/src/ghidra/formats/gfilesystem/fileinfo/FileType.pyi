from typing import List
import ghidra.formats.gfilesystem.fileinfo
import java.lang
import java.util


class FileType(java.lang.Enum):
    DIRECTORY: ghidra.formats.gfilesystem.fileinfo.FileType = DIRECTORY
    FILE: ghidra.formats.gfilesystem.fileinfo.FileType = FILE
    OTHER: ghidra.formats.gfilesystem.fileinfo.FileType = OTHER
    SYMBOLIC_LINK: ghidra.formats.gfilesystem.fileinfo.FileType = SYMBOLIC_LINK
    UNKNOWN: ghidra.formats.gfilesystem.fileinfo.FileType = UNKNOWN







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.formats.gfilesystem.fileinfo.FileType: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.formats.gfilesystem.fileinfo.FileType]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

