import ghidra.file.formats.ios.img3
import ghidra.program.model.data
import java.lang


class RsaShaTag(ghidra.file.formats.ios.img3.AbstractImg3Tag):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataLength(self) -> int: ...

    def getMagic(self) -> unicode: ...

    def getTotalLength(self) -> int: ...

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

