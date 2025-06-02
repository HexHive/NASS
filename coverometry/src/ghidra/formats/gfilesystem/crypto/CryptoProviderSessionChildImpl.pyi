from typing import Iterator
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.crypto
import ghidra.framework.generic.auth
import java.lang


class CryptoProviderSessionChildImpl(object, ghidra.formats.gfilesystem.crypto.CryptoSession):
    """
    A stub implementation of CryptoSession that relies on a parent instance.
    """





    def __init__(self, parentSession: ghidra.formats.gfilesystem.crypto.CryptoSession): ...



    def addSuccessfulPassword(self, fsrl: ghidra.formats.gfilesystem.FSRL, password: ghidra.framework.generic.auth.Password) -> None: ...

    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPasswordsFor(self, fsrl: ghidra.formats.gfilesystem.FSRL, prompt: unicode) -> Iterator[ghidra.framework.generic.auth.Password]: ...

    def hashCode(self) -> int: ...

    def isClosed(self) -> bool: ...

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
    def closed(self) -> bool: ...