from typing import List
import ghidra.file.formats.android.art
import java.lang
import java.util


class ArtStorageMode(java.lang.Enum):
    SIZE: int = 32
    kDefaultStorageMode: ghidra.file.formats.android.art.ArtStorageMode = kStorageModeUncompressed
    kStorageModeCount: ghidra.file.formats.android.art.ArtStorageMode = kStorageModeCount
    kStorageModeLZ4: ghidra.file.formats.android.art.ArtStorageMode = kStorageModeLZ4
    kStorageModeLZ4HC: ghidra.file.formats.android.art.ArtStorageMode = kStorageModeLZ4HC
    kStorageModeUncompressed: ghidra.file.formats.android.art.ArtStorageMode = kStorageModeUncompressed







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def get(__a0: int) -> ghidra.file.formats.android.art.ArtStorageMode: ...

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
    def valueOf(__a0: unicode) -> ghidra.file.formats.android.art.ArtStorageMode: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.file.formats.android.art.ArtStorageMode]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

