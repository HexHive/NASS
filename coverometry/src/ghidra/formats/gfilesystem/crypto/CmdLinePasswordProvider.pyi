from typing import Iterator
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.crypto
import ghidra.formats.gfilesystem.crypto.CryptoProvider
import ghidra.framework.generic.auth
import java.lang


class CmdLinePasswordProvider(object, ghidra.formats.gfilesystem.crypto.PasswordProvider):
    """
    A PasswordProvider that supplies passwords to decrypt files via the java jvm invocation.
 
     Example: java -Dfilesystem.passwords=/fullpath/to/textfile
 
     The password file is a plain text tabbed-csv file, where each line
     specifies a password and an optional file identifier.
 
     Example file contents, where each line is divided into fields by a tab
     character where the first field is the password and the second optional field
     is the file's identifying information (name, path, etc):
 
 
     password1   [tab]   myfirstzipfile.zip  supplies a password for the named file located in any directory
     someOtherPassword   [tab]   /full/path/tozipfile.zip  supplies password for file at specified location 
     anotherPassword [tab]   file:///full/path/tozipfile.zip|zip:///subdir/in/zip/somefile.txt  supplies password for file embedded inside a zip
     yetAnotherPassword  a password to try for any file that needs a password
 
    """

    CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME: unicode = u'filesystem.passwords'



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

