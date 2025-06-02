from typing import List
import ghidra.file.formats.android.oat.oatclass
import ghidra.program.model.data
import java.lang
import java.util


class OatClassStatusEnum_K(java.lang.Enum, ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum):
    kStatusError: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusError
    kStatusIdx: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusIdx
    kStatusInitialized: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusInitialized
    kStatusInitializing: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusInitializing
    kStatusLoaded: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusLoaded
    kStatusNotReady: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusNotReady
    kStatusResolved: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusResolved
    kStatusRetryVerificationAtRuntime: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusRetryVerificationAtRuntime
    kStatusVerified: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusVerified
    kStatusVerifying: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusVerifying
    kStatusVerifyingAtRuntime: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K = kStatusVerifyingAtRuntime







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, __a0: int) -> ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getValue(self) -> int: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def value(self) -> int: ...