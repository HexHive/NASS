from typing import List
import ghidra.app.util.bin
import ghidra.file.formats.android.vdex
import ghidra.file.formats.android.vdex.sections
import ghidra.program.model.data
import ghidra.util.task
import java.lang


class VdexHeader(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
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

    def getClass(self) -> java.lang.Class: ...

    def getDexChecksums(self) -> List[int]: ...

    def getDexHeaderList(self) -> List[object]: ...

    def getDexSectionHeader_002(self) -> ghidra.file.formats.android.vdex.sections.DexSectionHeader_002: ...

    def getDexStartOffset(self, __a0: int) -> long: ...

    def getMagic(self) -> unicode: ...

    def getQuickeningInfoSize(self) -> int: ...

    def getStringTable(self) -> ghidra.file.formats.android.vdex.VdexStringTable: ...

    def getVerifierDepsSize(self) -> int: ...

    def getVersion(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isDexHeaderEmbeddedInDataType(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parse(self, __a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.util.task.TaskMonitor) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def dexChecksums(self) -> List[int]: ...

    @property
    def dexHeaderEmbeddedInDataType(self) -> bool: ...

    @property
    def dexHeaderList(self) -> List[object]: ...

    @property
    def dexSectionHeader_002(self) -> ghidra.file.formats.android.vdex.sections.DexSectionHeader_002: ...

    @property
    def magic(self) -> unicode: ...

    @property
    def quickeningInfoSize(self) -> int: ...

    @property
    def stringTable(self) -> ghidra.file.formats.android.vdex.VdexStringTable: ...

    @property
    def verifierDepsSize(self) -> int: ...

    @property
    def version(self) -> unicode: ...