from typing import List
import ghidra.file.formats.android.art.image_method
import java.lang
import java.util


class ImageMethod_Oreo(java.lang.Enum):
    kImageMethodsCount: ghidra.file.formats.android.art.image_method.ImageMethod_Oreo = kImageMethodsCount
    kImtConflictMethod: ghidra.file.formats.android.art.image_method.ImageMethod_Oreo = kImtConflictMethod
    kImtUnimplementedMethod: ghidra.file.formats.android.art.image_method.ImageMethod_Oreo = kImtUnimplementedMethod
    kResolutionMethod: ghidra.file.formats.android.art.image_method.ImageMethod_Oreo = kResolutionMethod
    kSaveAllCalleeSavesMethod: ghidra.file.formats.android.art.image_method.ImageMethod_Oreo = kSaveAllCalleeSavesMethod
    kSaveEverythingMethod: ghidra.file.formats.android.art.image_method.ImageMethod_Oreo = kSaveEverythingMethod
    kSaveRefsAndArgsMethod: ghidra.file.formats.android.art.image_method.ImageMethod_Oreo = kSaveRefsAndArgsMethod
    kSaveRefsOnlyMethod: ghidra.file.formats.android.art.image_method.ImageMethod_Oreo = kSaveRefsOnlyMethod







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
    def valueOf(__a0: unicode) -> ghidra.file.formats.android.art.image_method.ImageMethod_Oreo: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.file.formats.android.art.image_method.ImageMethod_Oreo]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

