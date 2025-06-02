from typing import List
import ghidra.app.util.bin.format.golang
import ghidra.framework.options
import ghidra.program.model.listing
import java.lang
import java.util


class GoVer(java.lang.Enum):
    GOLANG_VERSION_PROPERTY_NAME: unicode = u'Golang go version'
    UNKNOWN: ghidra.app.util.bin.format.golang.GoVer = UNKNOWN
    V1_16: ghidra.app.util.bin.format.golang.GoVer = V1_16
    V1_17: ghidra.app.util.bin.format.golang.GoVer = V1_17
    V1_18: ghidra.app.util.bin.format.golang.GoVer = V1_18
    V1_19: ghidra.app.util.bin.format.golang.GoVer = V1_19
    V1_2: ghidra.app.util.bin.format.golang.GoVer = V1_2
    V1_20: ghidra.app.util.bin.format.golang.GoVer = V1_20







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromProgramProperties(__a0: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.golang.GoVer: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getMajor(self) -> int: ...

    def getMinor(self) -> int: ...

    def hashCode(self) -> int: ...

    def isAtLeast(self, __a0: ghidra.app.util.bin.format.golang.GoVer) -> bool: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def parse(__a0: unicode) -> ghidra.app.util.bin.format.golang.GoVer: ...

    @staticmethod
    def setProgramPropertiesWithOriginalVersionString(__a0: ghidra.framework.options.Options, __a1: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.golang.GoVer: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.util.bin.format.golang.GoVer]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def major(self) -> int: ...

    @property
    def minor(self) -> int: ...