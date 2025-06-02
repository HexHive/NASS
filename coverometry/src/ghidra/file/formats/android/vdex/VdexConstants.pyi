import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class VdexConstants(object):
    MAGIC: unicode = u'vdex'
    SUPPORTED_VERSIONS: List[unicode] = array(java.lang.String, [u'006', u'010', u'019', u'021', u'027'])
    VDEX_VERSION_006: unicode = u'006'
    VDEX_VERSION_010: unicode = u'010'
    VDEX_VERSION_019: unicode = u'019'
    VDEX_VERSION_021: unicode = u'021'
    VDEX_VERSION_027: unicode = u'027'
    kDexSectionVersion: unicode = u'002'
    kDexSectionVersionEmpty: unicode = u'000'
    kVdexNameInDmFile: unicode = u'primary.vdex'
    vdex_version_003: unicode = u'003'
    vdex_version_011: unicode = u'011'



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findVDEX(__a0: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isSupportedVersion(__a0: unicode) -> bool: ...

    @staticmethod
    def isVDEX(__a0: ghidra.program.model.listing.Program) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

