from typing import List
import ghidra.file.formats.android.bootimg
import ghidra.program.model.data
import java.lang


class BootImageHeaderV4(ghidra.file.formats.android.bootimg.BootImageHeaderV3):




    def __init__(self, __a0: ghidra.app.util.bin.BinaryReader): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCommandLine(self) -> unicode: ...

    def getHeaderSize(self) -> int: ...

    def getHeaderVersion(self) -> int: ...

    def getKernelOffset(self) -> long: ...

    def getKernelPageCount(self) -> int: ...

    def getKernelSize(self) -> int: ...

    def getMagic(self) -> unicode: ...

    def getOSVersion(self) -> int: ...

    def getPageSize(self) -> int: ...

    def getRamdiskOffset(self) -> int: ...

    def getRamdiskPageCount(self) -> int: ...

    def getRamdiskSize(self) -> int: ...

    def getReserved(self) -> List[int]: ...

    def getSecondOffset(self) -> long: ...

    def getSecondPageCount(self) -> int: ...

    def getSecondSize(self) -> int: ...

    def getSignatureSize(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def pageAlign(self, __a0: long) -> long: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def pageSize(self) -> int: ...

    @property
    def signatureSize(self) -> int: ...