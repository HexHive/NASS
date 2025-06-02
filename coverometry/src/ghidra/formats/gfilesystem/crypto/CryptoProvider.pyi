import ghidra.formats.gfilesystem.crypto
import java.lang
import java.util.function


class CryptoProvider(object):
    """
    Common interface for provider interfaces that provide crypto information.
 
     TODO: add CryptoKeyProvider.
    """






    class Session(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getCryptoProviders(self) -> ghidra.formats.gfilesystem.crypto.CryptoProviders: ...

        def getStateValue(self, __a0: ghidra.formats.gfilesystem.crypto.CryptoProvider, __a1: java.util.function.Supplier) -> object: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def setStateValue(self, __a0: ghidra.formats.gfilesystem.crypto.CryptoProvider, __a1: object) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def cryptoProviders(self) -> ghidra.formats.gfilesystem.crypto.CryptoProviders: ...





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

