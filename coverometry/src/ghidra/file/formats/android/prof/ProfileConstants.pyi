from typing import List
import ghidra.app.util.bin
import java.lang


class ProfileConstants(object):
    kDexMetadataProfileEntry: unicode = u'primary.prof'
    kProfileMagic: List[int] = array('b', [112, 114, 111, 0])
    kProfileMagicLength: int = 4
    kProfileVersionForBootImage_012: List[int] = array('b', [48, 49, 50, 0])
    kProfileVersionWithCounters: List[int] = array('b', [53, 48, 48, 0])
    kProfileVersion_008: List[int] = array('b', [48, 48, 56, 0])
    kProfileVersion_009: List[int] = array('b', [48, 48, 57, 0])
    kProfileVersion_010: List[int] = array('b', [48, 49, 48, 0])



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isProfile(__a0: ghidra.app.util.bin.ByteProvider) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def toString(__a0: List[int]) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

