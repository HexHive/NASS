from typing import List
import ghidra.dbg.attributes
import ghidra.dbg.util
import ghidra.program.model.address
import java.lang
import java.util


class ConversionUtils(java.lang.Enum):








    @staticmethod
    def addressFactoryToSpaceNameSet(__a0: ghidra.program.model.address.AddressFactory) -> ghidra.dbg.attributes.TargetStringList: ...

    @staticmethod
    def bigIntegerToBytes(__a0: int, __a1: long) -> List[int]: ...

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
    def valueOf(__a0: unicode) -> ghidra.dbg.util.ConversionUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.dbg.util.ConversionUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

