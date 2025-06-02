from typing import Iterator
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.crypto
import ghidra.formats.gfilesystem.crypto.CryptoProvider
import ghidra.framework.generic.auth
import java.lang


class PopupGUIPasswordProvider(object, ghidra.formats.gfilesystem.crypto.PasswordProvider):
    """
    Pops up up a GUI dialog prompting the user to enter a password for the specified file.
 
     The dialog is presented to the user when the iterator's hasNext() is called.
 
     Repeated requests to the same iterator will adjust the dialog's title with a "try count" to
     help the user understand the previous password was unsuccessful.
 
     Iterator's hasNext() will return false if the user has previously canceled the dialog,
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

