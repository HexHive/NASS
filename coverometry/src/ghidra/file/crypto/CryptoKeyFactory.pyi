import generic.jar
import ghidra.file.crypto
import java.lang


class CryptoKeyFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def forceReload() -> None: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getCryptoDirectory() -> generic.jar.ResourceFile: ...

    @staticmethod
    def getCryptoKey(__a0: unicode, __a1: unicode) -> ghidra.file.crypto.CryptoKey: ...

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

