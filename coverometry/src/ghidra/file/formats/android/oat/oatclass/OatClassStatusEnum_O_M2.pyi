from typing import List
import ghidra.file.formats.android.oat.oatclass
import ghidra.program.model.data
import java.lang
import java.util


class OatClassStatusEnum_O_M2(java.lang.Enum, ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum):
    kStatusErrorResolved: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusErrorResolved
    kStatusErrorUnresolved: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusErrorUnresolved
    kStatusIdx: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusIdx
    kStatusInitialized: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusInitialized
    kStatusInitializing: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusInitializing
    kStatusLoaded: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusLoaded
    kStatusMax: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusMax
    kStatusNotReady: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusNotReady
    kStatusResolved: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusResolved
    kStatusResolving: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusResolving
    kStatusRetired: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusRetired
    kStatusRetryVerificationAtRuntime: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusRetryVerificationAtRuntime
    kStatusSuperclassValidated: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusSuperclassValidated
    kStatusVerified: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusVerified
    kStatusVerifying: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusVerifying
    kStatusVerifyingAtRuntime: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2 = kStatusVerifyingAtRuntime







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
    def valueOf(__a0: unicode) -> ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def value(self) -> int: ...