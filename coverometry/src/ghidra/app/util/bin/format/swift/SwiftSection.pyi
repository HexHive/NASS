from typing import List
import ghidra.app.util.bin.format.swift
import java.lang
import java.util


class SwiftSection(java.lang.Enum):
    BLOCK_ACFUNCS: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_ACFUNCS
    BLOCK_ASSOCTY: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_ASSOCTY
    BLOCK_BUILTIN: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_BUILTIN
    BLOCK_CAPTURE: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_CAPTURE
    BLOCK_CONFORM: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_CONFORM
    BLOCK_ENTRY: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_ENTRY
    BLOCK_FIELDMD: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_FIELDMD
    BLOCK_MPENUM: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_MPENUM
    BLOCK_PROTOCS: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_PROTOCS
    BLOCK_REFLSTR: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_REFLSTR
    BLOCK_TYPEREF: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_TYPEREF
    BLOCK_TYPES: ghidra.app.util.bin.format.swift.SwiftSection = BLOCK_TYPES







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getSwiftSectionNames(self) -> List[object]: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.swift.SwiftSection: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.util.bin.format.swift.SwiftSection]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def swiftSectionNames(self) -> List[object]: ...