from typing import List
import ghidra.program.model.data
import java.lang
import java.util


class PointerType(java.lang.Enum):
    DEFAULT: ghidra.program.model.data.PointerType = DEFAULT
    FILE_OFFSET: ghidra.program.model.data.PointerType = FILE_OFFSET
    IMAGE_BASE_RELATIVE: ghidra.program.model.data.PointerType = IMAGE_BASE_RELATIVE
    RELATIVE: ghidra.program.model.data.PointerType = RELATIVE







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
    def valueOf(__a0: int) -> ghidra.program.model.data.PointerType: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.program.model.data.PointerType: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.program.model.data.PointerType]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

