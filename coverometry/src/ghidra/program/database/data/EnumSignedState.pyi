from typing import List
import ghidra.program.database.data
import java.lang
import java.util


class EnumSignedState(java.lang.Enum):
    INVALID: ghidra.program.database.data.EnumSignedState = INVALID
    NONE: ghidra.program.database.data.EnumSignedState = NONE
    SIGNED: ghidra.program.database.data.EnumSignedState = SIGNED
    UNSIGNED: ghidra.program.database.data.EnumSignedState = UNSIGNED







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
    def valueOf(__a0: unicode) -> ghidra.program.database.data.EnumSignedState: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.program.database.data.EnumSignedState]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

