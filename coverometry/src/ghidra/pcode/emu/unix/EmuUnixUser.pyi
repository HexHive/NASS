import java.lang


class EmuUnixUser(object):
    DEFAULT_USER: ghidra.pcode.emu.unix.EmuUnixUser = ghidra.pcode.emu.unix.EmuUnixUser@6bee932d
    gids: java.util.Collection
    uid: int



    def __init__(self, __a0: int, __a1: java.util.Collection): ...



    def equals(self, __a0: object) -> bool: ...

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

