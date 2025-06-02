from typing import List
import ghidra.file.formats.android.verifier
import java.lang
import java.util


class MethodType(java.lang.Enum):
    METHOD_DIRECT: ghidra.file.formats.android.verifier.MethodType = METHOD_DIRECT
    METHOD_INTERFACE: ghidra.file.formats.android.verifier.MethodType = METHOD_INTERFACE
    METHOD_POLYMORPHIC: ghidra.file.formats.android.verifier.MethodType = METHOD_POLYMORPHIC
    METHOD_STATIC: ghidra.file.formats.android.verifier.MethodType = METHOD_STATIC
    METHOD_SUPER: ghidra.file.formats.android.verifier.MethodType = METHOD_SUPER
    METHOD_UNKNOWN: ghidra.file.formats.android.verifier.MethodType = METHOD_UNKNOWN
    METHOD_VIRTUAL: ghidra.file.formats.android.verifier.MethodType = METHOD_VIRTUAL







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
    def valueOf(__a0: unicode) -> ghidra.file.formats.android.verifier.MethodType: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.file.formats.android.verifier.MethodType]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

