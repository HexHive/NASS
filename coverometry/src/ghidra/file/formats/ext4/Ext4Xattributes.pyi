import ghidra.app.util.bin
import ghidra.file.formats.ext4
import java.lang


class Ext4Xattributes(object):








    def equals(self, __a0: object) -> bool: ...

    def getAttribute(self, __a0: unicode) -> ghidra.file.formats.ext4.Ext4XattrEntry: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def readInodeXAttributes(__a0: ghidra.app.util.bin.BinaryReader, __a1: long) -> ghidra.file.formats.ext4.Ext4Xattributes: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

