from typing import List
import ghidra.app.util.bin.format.macos.cfm
import java.lang
import java.util


class CFragSymbolClass(java.lang.Enum):
    kCodeCFragSymbol: ghidra.app.util.bin.format.macos.cfm.CFragSymbolClass = kCodeCFragSymbol
    kDataCFragSymbol: ghidra.app.util.bin.format.macos.cfm.CFragSymbolClass = kDataCFragSymbol
    kGlueCFragSymbol: ghidra.app.util.bin.format.macos.cfm.CFragSymbolClass = kGlueCFragSymbol
    kTOCCFragSymbol: ghidra.app.util.bin.format.macos.cfm.CFragSymbolClass = kTOCCFragSymbol
    kTVectorCFragSymbol: ghidra.app.util.bin.format.macos.cfm.CFragSymbolClass = kTVectorCFragSymbol







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
    def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.macos.cfm.CFragSymbolClass: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.util.bin.format.macos.cfm.CFragSymbolClass]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

