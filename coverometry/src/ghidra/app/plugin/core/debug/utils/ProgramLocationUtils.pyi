from typing import List
import ghidra.app.plugin.core.debug.utils
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang
import java.util


class ProgramLocationUtils(java.lang.Enum):








    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fixLocation(__a0: ghidra.program.util.ProgramLocation, __a1: bool) -> ghidra.program.util.ProgramLocation: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def replaceAddress(__a0: ghidra.program.util.ProgramLocation, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation: ...

    @staticmethod
    def replaceProgram(__a0: ghidra.program.util.ProgramLocation, __a1: ghidra.program.model.listing.Program) -> ghidra.program.util.ProgramLocation: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.plugin.core.debug.utils.ProgramLocationUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.plugin.core.debug.utils.ProgramLocationUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

