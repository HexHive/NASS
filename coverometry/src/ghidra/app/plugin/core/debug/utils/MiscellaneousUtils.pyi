from typing import List
import ghidra.app.plugin.core.debug.utils
import ghidra.program.model.address
import java.awt
import java.beans
import java.lang
import java.util
import java.util.function


class MiscellaneousUtils(java.lang.Enum):
    HEX_BIT64: unicode = u'0x10000000000000000'







    @staticmethod
    def collectUniqueInstances(__a0: java.lang.Class, __a1: java.util.Map, __a2: java.util.function.Function) -> None: ...

    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    @staticmethod
    def getEditorComponent(__a0: java.beans.PropertyEditor) -> java.awt.Component: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def lengthMin(__a0: long, __a1: long) -> long: ...

    @staticmethod
    def lengthToString(__a0: long) -> unicode: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def parseLength(__a0: unicode, __a1: long) -> long: ...

    @staticmethod
    def revalidateLengthByRange(__a0: ghidra.program.model.address.AddressRange, __a1: long) -> long: ...

    @staticmethod
    def rigFocusAndEnter(__a0: java.awt.Component, __a1: java.lang.Runnable) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.plugin.core.debug.utils.MiscellaneousUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.plugin.core.debug.utils.MiscellaneousUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

