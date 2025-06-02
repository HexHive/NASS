from typing import List
import ghidra.file.formats.android.oat.oatclass
import ghidra.program.model.data
import java.lang
import java.util


class OatClassStatusEnum_R_S_T(java.lang.Enum, ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum):
    kErrorResolved: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kErrorResolved
    kErrorUnresolved: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kErrorUnresolved
    kIdx: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kIdx
    kInitialized: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kInitialized
    kInitializing: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kInitializing
    kLast: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kLast
    kLoaded: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kLoaded
    kNotReady: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kNotReady
    kResolved: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kResolved
    kResolving: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kResolving
    kRetired: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kRetired
    kRetryVerificationAtRuntime: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kRetryVerificationAtRuntime
    kSuperclassValidated: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kSuperclassValidated
    kVerified: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kVerified
    kVerifiedNeedsAccessChecks: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kVerifiedNeedsAccessChecks
    kVerifying: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kVerifying
    kVisiblyInitialized: ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T = kVisiblyInitialized







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
    def valueOf(__a0: unicode) -> ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def value(self) -> int: ...