from typing import List
import ghidra.framework
import java.lang
import java.util


class Architecture(java.lang.Enum):
    ARM_64: ghidra.framework.Architecture = ARM_64(amd64)
    POWERPC: ghidra.framework.Architecture = POWERPC(amd64)
    POWERPC_64: ghidra.framework.Architecture = POWERPC_64(amd64)
    UNKNOWN: ghidra.framework.Architecture = UNKNOWN(amd64)
    X86: ghidra.framework.Architecture = X86(amd64)
    X86_64: ghidra.framework.Architecture = X86_64(amd64)







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
    def valueOf(__a0: unicode) -> ghidra.framework.Architecture: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.framework.Architecture]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

