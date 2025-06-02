from typing import Iterator
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.crypto
import ghidra.formats.gfilesystem.crypto.CryptoProvider
import ghidra.framework.generic.auth
import java.lang


class CachedPasswordProvider(object, ghidra.formats.gfilesystem.crypto.PasswordProvider):
    """
    Caches passwords used to unlock a file.
 
     Threadsafe.
    """





    def __init__(self): ...



    def addPassword(self, fsrl: ghidra.formats.gfilesystem.FSRL, password: ghidra.framework.generic.auth.Password) -> None:
        """
        Adds a password / file combo to the cache.
        @param fsrl {@link FSRL} file
        @param password password to unlock the file.  Specified {@link Password} is
         only copied, clearing is still callers responsibility
        """
        ...

    def clearCache(self) -> None:
        """
        Remove all cached information.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCount(self) -> int:
        """
        Returns the number of items in cache
        @return number of items in cache
        """
        ...

    def getPasswordsFor(self, fsrl: ghidra.formats.gfilesystem.FSRL, prompt: unicode, session: ghidra.formats.gfilesystem.crypto.CryptoProvider.Session) -> Iterator[ghidra.framework.generic.auth.Password]: ...

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
    def count(self) -> int: ...