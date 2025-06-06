from typing import List
import ghidra.app.util.bin
import ghidra.file.formats.android.oat
import ghidra.file.formats.android.oat.bundle
import ghidra.file.formats.android.oat.headers
import ghidra.program.model.data
import java.lang


class OatHeader_124(ghidra.file.formats.android.oat.headers.OatHeader_064):




    def __init__(self, __a0: ghidra.app.util.bin.BinaryReader): ...



    def equals(self, __a0: object) -> bool: ...

    def getChecksum(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDexFileCount(self) -> int: ...

    def getExecutableOffset(self) -> int: ...

    def getInstructionSet(self) -> ghidra.file.formats.android.oat.OatInstructionSet: ...

    def getInstructionSetFeaturesBitmap(self) -> int: ...

    def getInterpreterToInterpreterBridgeOffset(self) -> int: ...

    def getJniDlsymLookupOffset(self) -> int: ...

    def getKeyValueStoreSize(self) -> int: ...

    def getMagic(self) -> unicode: ...

    def getOatDexFileList(self) -> List[object]: ...

    def getOatDexFilesOffset(self, __a0: ghidra.app.util.bin.BinaryReader) -> int: ...

    def getQuickGenericJniTrampolineOffset(self) -> int: ...

    def getQuickImtConflictTrampolineOffset(self) -> int: ...

    def getQuickResolutionTrampolineOffset(self) -> int: ...

    def getQuickToInterpreterBridgeOffset(self) -> int: ...

    def getVersion(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parse(self, __a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.file.formats.android.oat.bundle.OatBundle) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

