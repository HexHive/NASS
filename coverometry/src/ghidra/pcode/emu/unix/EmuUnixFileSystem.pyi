from typing import List
import ghidra.pcode.emu.unix
import java.lang
import java.util


class EmuUnixFileSystem(object):





    class OpenFlag(java.lang.Enum):
        O_APPEND: ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag = O_APPEND
        O_CREAT: ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag = O_CREAT
        O_RDONLY: ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag = O_RDONLY
        O_RDWR: ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag = O_RDWR
        O_TRUNC: ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag = O_TRUNC
        O_WRONLY: ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag = O_WRONLY







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        @staticmethod
        def isRead(__a0: java.util.Collection) -> bool: ...

        @staticmethod
        def isWrite(__a0: java.util.Collection) -> bool: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        @overload
        @staticmethod
        def set(__a0: List[ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag]) -> java.util.Set: ...

        @overload
        @staticmethod
        def set(__a0: java.util.Collection) -> java.util.Set: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def createOrGetFile(self, __a0: unicode, __a1: int) -> ghidra.pcode.emu.unix.EmuUnixFile: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFile(self, __a0: unicode) -> ghidra.pcode.emu.unix.EmuUnixFile: ...

    def hashCode(self) -> int: ...

    def newFile(self, __a0: unicode, __a1: int) -> ghidra.pcode.emu.unix.EmuUnixFile: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def open(self, __a0: unicode, __a1: java.util.Set, __a2: ghidra.pcode.emu.unix.EmuUnixUser, __a3: int) -> ghidra.pcode.emu.unix.EmuUnixFile: ...

    def putFile(self, __a0: unicode, __a1: ghidra.pcode.emu.unix.EmuUnixFile) -> None: ...

    def toString(self) -> unicode: ...

    def unlink(self, __a0: unicode, __a1: ghidra.pcode.emu.unix.EmuUnixUser) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

