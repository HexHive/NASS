import ghidra.file.formats.android.oat.quickmethod
import ghidra.program.model.data
import java.lang


class OatQuickMethodHeader_S_T(ghidra.file.formats.android.oat.quickmethod.OatQuickMethodHeader):
    kCodeInfoMask: int = 1073741823
    kCodeSizeMask: int = 1073741823
    kIsCodeInfoMask: int = 1073741824
    kShouldDeoptimizeMask: int = -2147483648







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeSize(self) -> int: ...

    def getData(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def codeSize(self) -> int: ...

    @property
    def data(self) -> int: ...