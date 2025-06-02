from typing import List
import ghidra.app.util.demangler.gnu
import java.lang
import java.util


class GnuDemanglerFormat(java.lang.Enum):
    ARM: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = ARM
    AUTO: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = AUTO
    DLANG: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = DLANG
    EDG: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = EDG
    GNAT: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = GNAT
    GNU: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = GNU
    GNUV3: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = GNUV3
    HP: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = HP
    JAVA: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = JAVA
    LUCID: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = LUCID
    RUST: ghidra.app.util.demangler.gnu.GnuDemanglerFormat = RUST







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getFormat(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isAvailable(self, __a0: bool) -> bool: ...

    def isDeprecatedFormat(self) -> bool: ...

    def isModernFormat(self) -> bool: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.util.demangler.gnu.GnuDemanglerFormat: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.util.demangler.gnu.GnuDemanglerFormat]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def deprecatedFormat(self) -> bool: ...

    @property
    def format(self) -> unicode: ...

    @property
    def modernFormat(self) -> bool: ...