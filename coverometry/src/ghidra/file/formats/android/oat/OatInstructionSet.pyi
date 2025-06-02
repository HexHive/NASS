from typing import List
import ghidra.file.formats.android.oat
import java.lang
import java.util


class OatInstructionSet(java.lang.Enum):
    DISPLAY_NAME: unicode = u'instruction_set_'
    kArm: ghidra.file.formats.android.oat.OatInstructionSet = kArm
    kArm64: ghidra.file.formats.android.oat.OatInstructionSet = kArm64
    kMips: ghidra.file.formats.android.oat.OatInstructionSet = kMips
    kMips64: ghidra.file.formats.android.oat.OatInstructionSet = kMips64
    kNone: ghidra.file.formats.android.oat.OatInstructionSet = kNone
    kThumb2: ghidra.file.formats.android.oat.OatInstructionSet = kThumb2
    kX86: ghidra.file.formats.android.oat.OatInstructionSet = kX86
    kX86_64: ghidra.file.formats.android.oat.OatInstructionSet = kX86_64







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
    def valueOf(__a0: int) -> ghidra.file.formats.android.oat.OatInstructionSet: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.file.formats.android.oat.OatInstructionSet: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.file.formats.android.oat.OatInstructionSet]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

