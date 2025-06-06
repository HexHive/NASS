import ghidra.file.formats.ext4
import java.lang


class Ext4File(object):




    def __init__(self, __a0: unicode, __a1: ghidra.file.formats.ext4.Ext4Inode): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getInode(self) -> ghidra.file.formats.ext4.Ext4Inode: ...

    def getName(self) -> unicode: ...

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
    def inode(self) -> ghidra.file.formats.ext4.Ext4Inode: ...

    @property
    def name(self) -> unicode: ...