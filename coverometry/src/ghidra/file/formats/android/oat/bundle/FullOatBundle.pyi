from typing import List
import ghidra.file.formats.android.art
import ghidra.file.formats.android.dex.format
import ghidra.file.formats.android.oat
import ghidra.file.formats.android.oat.bundle
import ghidra.file.formats.android.vdex
import java.lang


class FullOatBundle(object, ghidra.file.formats.android.oat.bundle.OatBundle):
    APK: unicode = u'.apk'
    ART: unicode = u'.art'
    CDEX: unicode = u'cdex'
    CLASSES: unicode = u'classes'
    DEX: unicode = u'.dex'
    JAR: unicode = u'.jar'
    OAT: unicode = u'.oat'
    ODEX: unicode = u'.odex'
    VDEX: unicode = u'.vdex'







    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getArtHeader(self) -> ghidra.file.formats.android.art.ArtHeader: ...

    def getClass(self) -> java.lang.Class: ...

    def getDexHeaderByChecksum(self, __a0: int) -> ghidra.file.formats.android.dex.format.DexHeader: ...

    def getDexHeaders(self) -> List[object]: ...

    def getOatHeader(self) -> ghidra.file.formats.android.oat.OatHeader: ...

    def getVdexHeader(self) -> ghidra.file.formats.android.vdex.VdexHeader: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def artHeader(self) -> ghidra.file.formats.android.art.ArtHeader: ...

    @property
    def dexHeaders(self) -> List[object]: ...

    @property
    def oatHeader(self) -> ghidra.file.formats.android.oat.OatHeader: ...

    @property
    def vdexHeader(self) -> ghidra.file.formats.android.vdex.VdexHeader: ...