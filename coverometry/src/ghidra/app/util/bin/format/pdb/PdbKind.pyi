from typing import List
import ghidra.app.util.bin.format.pdb
import java.lang
import java.util


class PdbKind(java.lang.Enum):
    LOCAL: ghidra.app.util.bin.format.pdb.PdbKind = LOCAL
    MEMBER: ghidra.app.util.bin.format.pdb.PdbKind = MEMBER
    OBJECT_POINTER: ghidra.app.util.bin.format.pdb.PdbKind = OBJECT_POINTER
    PARAMETER: ghidra.app.util.bin.format.pdb.PdbKind = PARAMETER
    STATIC_LOCAL: ghidra.app.util.bin.format.pdb.PdbKind = STATIC_LOCAL
    STATIC_MEMBER: ghidra.app.util.bin.format.pdb.PdbKind = STATIC_MEMBER
    STRUCTURE: ghidra.app.util.bin.format.pdb.PdbKind = STRUCTURE
    UNION: ghidra.app.util.bin.format.pdb.PdbKind = UNION
    UNKNOWN: ghidra.app.util.bin.format.pdb.PdbKind = UNKNOWN







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getCamelName(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def parse(__a0: unicode) -> ghidra.app.util.bin.format.pdb.PdbKind: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.pdb.PdbKind: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.util.bin.format.pdb.PdbKind]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def camelName(self) -> unicode: ...