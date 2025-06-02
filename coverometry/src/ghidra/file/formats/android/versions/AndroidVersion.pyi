from typing import List
import ghidra.file.formats.android.versions
import java.lang
import java.util


class AndroidVersion(java.lang.Enum):
    INVALID_API_VALUE: int = -1
    UNKNOWN: ghidra.file.formats.android.versions.AndroidVersion = UNKNOWN
    VERSION_10: ghidra.file.formats.android.versions.AndroidVersion = VERSION_10
    VERSION_11: ghidra.file.formats.android.versions.AndroidVersion = VERSION_11
    VERSION_12: ghidra.file.formats.android.versions.AndroidVersion = VERSION_12
    VERSION_12_L: ghidra.file.formats.android.versions.AndroidVersion = VERSION_12_L
    VERSION_13: ghidra.file.formats.android.versions.AndroidVersion = VERSION_13
    VERSION_1_5: ghidra.file.formats.android.versions.AndroidVersion = VERSION_1_5
    VERSION_1_6: ghidra.file.formats.android.versions.AndroidVersion = VERSION_1_6
    VERSION_2_0: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_0
    VERSION_2_0_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_0_1
    VERSION_2_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_1
    VERSION_2_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_2
    VERSION_2_2_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_2_1
    VERSION_2_2_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_2_2
    VERSION_2_2_3: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_2_3
    VERSION_2_3: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_3
    VERSION_2_3_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_3_1
    VERSION_2_3_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_3_2
    VERSION_2_3_3: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_3_3
    VERSION_2_3_4: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_3_4
    VERSION_2_3_5: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_3_5
    VERSION_2_3_6: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_3_6
    VERSION_2_3_7: ghidra.file.formats.android.versions.AndroidVersion = VERSION_2_3_7
    VERSION_3_0: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_0
    VERSION_3_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_1
    VERSION_3_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_2
    VERSION_3_2_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_2_1
    VERSION_3_2_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_2_2
    VERSION_3_2_3: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_2_3
    VERSION_3_2_4: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_2_4
    VERSION_3_2_5: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_2_5
    VERSION_3_2_6: ghidra.file.formats.android.versions.AndroidVersion = VERSION_3_2_6
    VERSION_4_0: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_0
    VERSION_4_0_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_0_1
    VERSION_4_0_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_0_2
    VERSION_4_0_3: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_0_3
    VERSION_4_0_4: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_0_4
    VERSION_4_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_1
    VERSION_4_1_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_1_1
    VERSION_4_1_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_1_2
    VERSION_4_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_2
    VERSION_4_2_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_2_1
    VERSION_4_2_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_2_2
    VERSION_4_3: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_3
    VERSION_4_3_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_3_1
    VERSION_4_4: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_4
    VERSION_4_4_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_4_1
    VERSION_4_4_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_4_2
    VERSION_4_4_3: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_4_3
    VERSION_4_4_4: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_4_4
    VERSION_4_4_W: ghidra.file.formats.android.versions.AndroidVersion = VERSION_4_4_W
    VERSION_5_0: ghidra.file.formats.android.versions.AndroidVersion = VERSION_5_0
    VERSION_5_0_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_5_0_1
    VERSION_5_0_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_5_0_2
    VERSION_5_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_5_1
    VERSION_5_1_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_5_1_1
    VERSION_6_0: ghidra.file.formats.android.versions.AndroidVersion = VERSION_6_0
    VERSION_6_0_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_6_0_1
    VERSION_7_0: ghidra.file.formats.android.versions.AndroidVersion = VERSION_7_0
    VERSION_7_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_7_1
    VERSION_7_1_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_7_1_1
    VERSION_7_1_2: ghidra.file.formats.android.versions.AndroidVersion = VERSION_7_1_2
    VERSION_8_0: ghidra.file.formats.android.versions.AndroidVersion = VERSION_8_0
    VERSION_8_1: ghidra.file.formats.android.versions.AndroidVersion = VERSION_8_1
    VERSION_9: ghidra.file.formats.android.versions.AndroidVersion = VERSION_9







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getApiVersion(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getVersionLetter(self) -> int: ...

    def getVersionName(self) -> unicode: ...

    def getVersionNumber(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.file.formats.android.versions.AndroidVersion: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.file.formats.android.versions.AndroidVersion]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def apiVersion(self) -> int: ...

    @property
    def versionLetter(self) -> int: ...

    @property
    def versionName(self) -> unicode: ...

    @property
    def versionNumber(self) -> unicode: ...