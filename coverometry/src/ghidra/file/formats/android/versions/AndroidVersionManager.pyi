from typing import List
import ghidra.file.formats.android.versions
import java.lang


class AndroidVersionManager(object):
    PLATFORM_BUILD_VERSION_CODE: unicode = u'platformBuildVersionCode'
    PLATFORM_BUILD_VERSION_NAME: unicode = u'platformBuildVersionName'



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getByAPI(__a0: int) -> List[object]: ...

    @overload
    @staticmethod
    def getByLetter(__a0: int) -> List[object]: ...

    @overload
    @staticmethod
    def getByLetter(__a0: unicode) -> List[object]: ...

    @staticmethod
    def getByName(__a0: unicode) -> List[object]: ...

    @staticmethod
    def getByNumber(__a0: unicode) -> ghidra.file.formats.android.versions.AndroidVersion: ...

    @staticmethod
    def getByPlatformBuildVersion(__a0: unicode, __a1: unicode) -> ghidra.file.formats.android.versions.AndroidVersion: ...

    def getClass(self) -> java.lang.Class: ...

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

