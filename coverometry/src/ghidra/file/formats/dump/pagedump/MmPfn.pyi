import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class MmPfn(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'PAGEDUMP_PHYS_MEM_RUN'
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word







    def equals(self, __a0: object) -> bool: ...

    def getBlink(self) -> long: ...

    def getClass(self) -> java.lang.Class: ...

    def getFlags(self) -> long: ...

    def getOrigPte(self) -> long: ...

    def getParent(self) -> int: ...

    def getPteAddress(self) -> long: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setBlink(self, __a0: long) -> None: ...

    def setFlags(self, __a0: long) -> None: ...

    def setOrigPte(self, __a0: long) -> None: ...

    def setParent(self, __a0: int) -> None: ...

    def setPteAddress(self, __a0: long) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def blink(self) -> long: ...

    @blink.setter
    def blink(self, value: long) -> None: ...

    @property
    def flags(self) -> long: ...

    @flags.setter
    def flags(self, value: long) -> None: ...

    @property
    def origPte(self) -> long: ...

    @origPte.setter
    def origPte(self, value: long) -> None: ...

    @property
    def parent(self) -> int: ...

    @parent.setter
    def parent(self, value: int) -> None: ...

    @property
    def pteAddress(self) -> long: ...

    @pteAddress.setter
    def pteAddress(self, value: long) -> None: ...