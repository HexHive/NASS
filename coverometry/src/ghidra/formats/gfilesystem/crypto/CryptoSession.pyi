from typing import Iterator
import ghidra.formats.gfilesystem
import ghidra.framework.generic.auth
import java.io
import java.lang


class CryptoSession(java.io.Closeable, object):
    """
    Provides the caller with the ability to perform crypto querying operations
     for a group of related files.
 
     Typically used to query passwords and to add known good passwords
     to caches for later re-retrieval.
 
     Closing a CryptoSession instance does not invalidate the instance, instead is is a suggestion
     that the instance should not be used for any further nested sessions.
 
     See CryptoProviders#newSession().
    """









    def addSuccessfulPassword(self, fsrl: ghidra.formats.gfilesystem.FSRL, password: ghidra.framework.generic.auth.Password) -> None:
        """
        Pushes a known good password into a cache for later re-retrieval.
        @param fsrl {@link FSRL} path to the file that was unlocked by the password
        @param password the good password
        """
        ...

    def close(self) -> None:
        """
        Closes this session.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPasswordsFor(self, fsrl: ghidra.formats.gfilesystem.FSRL, prompt: unicode) -> Iterator[ghidra.framework.generic.auth.Password]:
        """
        Returns a sequence of passwords (sorted by quality) that may apply to
         the specified file.
        @param fsrl {@link FSRL} path to the password protected file
        @param prompt optional prompt that may be displayed to a user
        @return {@link Iterator} of possible passwords
        """
        ...

    def hashCode(self) -> int: ...

    def isClosed(self) -> bool:
        """
        Returns true if this session has been closed.
        @return boolean true if closed
        """
        ...

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