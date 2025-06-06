from typing import List
import ghidra.app.util.bin
import ghidra.file.formats.android.art
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class ImageSections_Nougat(ghidra.file.formats.android.art.ArtImageSections):
    kSectionArtFields: int = 1
    kSectionArtMethods: int = 2
    kSectionClassTable: int = 7
    kSectionCount: int = 9
    kSectionDexCacheArrays: int = 5
    kSectionIMTConflictTables: int = 4
    kSectionImageBitmap: int = 8
    kSectionInternedStrings: int = 6
    kSectionObjects: int = 0
    kSectionRuntimeMethods: int = 3



    def __init__(self, __a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.file.formats.android.art.ArtHeader): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getSectionList(self) -> List[object]: ...

    def get_kSectionArtFields(self) -> int: ...

    def get_kSectionArtMethods(self) -> int: ...

    def get_kSectionClassTable(self) -> int: ...

    def get_kSectionCount(self) -> int: ...

    def get_kSectionDexCacheArrays(self) -> int: ...

    def get_kSectionIMTConflictTables(self) -> int: ...

    def get_kSectionImTables(self) -> int: ...

    def get_kSectionImageBitmap(self) -> int: ...

    def get_kSectionInternedStrings(self) -> int: ...

    def get_kSectionMetadata(self) -> int: ...

    def get_kSectionObjects(self) -> int: ...

    def get_kSectionRuntimeMethods(self) -> int: ...

    def get_kSectionStringReferenceOffsets(self) -> int: ...

    def hashCode(self) -> int: ...

    def markup(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.util.task.TaskMonitor) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parse(self, __a0: ghidra.app.util.bin.BinaryReader) -> None: ...

    def parseSections(self, __a0: ghidra.app.util.bin.BinaryReader) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def _kSectionArtFields(self) -> int: ...

    @property
    def _kSectionArtMethods(self) -> int: ...

    @property
    def _kSectionClassTable(self) -> int: ...

    @property
    def _kSectionCount(self) -> int: ...

    @property
    def _kSectionDexCacheArrays(self) -> int: ...

    @property
    def _kSectionIMTConflictTables(self) -> int: ...

    @property
    def _kSectionImTables(self) -> int: ...

    @property
    def _kSectionImageBitmap(self) -> int: ...

    @property
    def _kSectionInternedStrings(self) -> int: ...

    @property
    def _kSectionMetadata(self) -> int: ...

    @property
    def _kSectionObjects(self) -> int: ...

    @property
    def _kSectionRuntimeMethods(self) -> int: ...

    @property
    def _kSectionStringReferenceOffsets(self) -> int: ...