from typing import Iterator
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.crypto
import ghidra.formats.gfilesystem.crypto.CryptoProvider
import ghidra.framework.generic.auth
import java.lang


class PasswordProvider(ghidra.formats.gfilesystem.crypto.CryptoProvider, object):
    """
    Instances of this interface provide passwords to decrypt files.
 
     Instances are typically not called directly, instead are used 
     by a CryptoSession along with other provider instances to provide
     a balanced breakfast. 
 
     Multiple passwords can be returned for each request with the
     assumption that the consumer of the values can test and validate each one
     to find the correct value.  Conversely, it would not be appropriate to use this to get
     a password for a login service that may lock the requester out after a small number
     of failed attempts.
 
     TODO: add negative password result that can be persisted / cached so
     user isn't spammed with requests for an unknown password during batch / recursive
     operations.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPasswordsFor(self, fsrl: ghidra.formats.gfilesystem.FSRL, prompt: unicode, session: ghidra.formats.gfilesystem.crypto.CryptoProvider.Session) -> Iterator[ghidra.framework.generic.auth.Password]:
        """
        Returns a sequence of passwords (ordered by quality) that may apply to
         the specified file.
        @param fsrl {@link FSRL} path to the password protected file
        @param prompt optional prompt that may be displayed to a user
        @param session a place to hold state values that persist across
         related queries
        @return {@link Iterator} of possible passwords
        """
        ...

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

