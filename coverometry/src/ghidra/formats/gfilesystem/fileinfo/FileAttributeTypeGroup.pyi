from typing import List
import ghidra.formats.gfilesystem.fileinfo
import java.lang
import java.util


class FileAttributeTypeGroup(java.lang.Enum):
    ADDITIONAL_INFO: ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup = ADDITIONAL_INFO
    DATE_INFO: ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup = DATE_INFO
    ENCRYPTION_INFO: ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup = ENCRYPTION_INFO
    GENERAL_INFO: ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup = GENERAL_INFO
    MISC_INFO: ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup = MISC_INFO
    OWNERSHIP_INFO: ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup = OWNERSHIP_INFO
    PERMISSION_INFO: ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup = PERMISSION_INFO
    SIZE_INFO: ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup = SIZE_INFO







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getDescriptiveName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def descriptiveName(self) -> unicode: ...