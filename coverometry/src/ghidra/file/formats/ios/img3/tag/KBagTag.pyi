from typing import List
import ghidra.file.formats.ios.img3
import ghidra.program.model.data
import java.lang


class KBagTag(ghidra.file.formats.ios.img3.AbstractImg3Tag):
    AES_128: int = 128
    AES_192: int = 192
    AES_256: int = 256
    MAGIC: unicode = u'KBAG'







    def equals(self, __a0: object) -> bool: ...

    def getAesType(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataLength(self) -> int: ...

    def getEncryptionIV(self) -> List[int]: ...

    def getEncryptionKey(self) -> List[int]: ...

    def getIVKeyCryptState(self) -> int: ...

    def getMagic(self) -> unicode: ...

    def getTotalLength(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def IVKeyCryptState(self) -> int: ...

    @property
    def aesType(self) -> int: ...

    @property
    def encryptionIV(self) -> List[int]: ...

    @property
    def encryptionKey(self) -> List[int]: ...