import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class ArtConstants(object):
    ART_NAME: unicode = u'Android Runtime (ART)'
    ART_VERSION_005: unicode = u'005'
    ART_VERSION_009: unicode = u'009'
    ART_VERSION_012: unicode = u'012'
    ART_VERSION_017: unicode = u'017'
    ART_VERSION_029: unicode = u'029'
    ART_VERSION_030: unicode = u'030'
    ART_VERSION_043: unicode = u'043'
    ART_VERSION_044: unicode = u'044'
    ART_VERSION_046: unicode = u'046'
    ART_VERSION_056: unicode = u'056'
    ART_VERSION_074: unicode = u'074'
    ART_VERSION_085: unicode = u'085'
    ART_VERSION_099: unicode = u'099'
    ART_VERSION_106: unicode = u'106'
    MAGIC: unicode = u'art\n'
    SUPPORTED_VERSIONS: List[unicode] = array(java.lang.String, [u'005', u'009', u'012', u'017', u'029', u'030', u'043', u'044', u'046', u'056', u'074', u'085', u'099', u'106'])
    VERSION_LENGTH: int = 4



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findART(__a0: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isART(__a0: ghidra.program.model.listing.Program) -> bool: ...

    @staticmethod
    def isSupportedVersion(__a0: unicode) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

