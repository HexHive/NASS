import ghidra.formats.gfilesystem.crypto
import java.lang


class CryptoProviders(object):
    """
    Registry of CryptoProvider and #newSession().
    """









    def equals(self, __a0: object) -> bool: ...

    def getCachedCryptoProvider(self) -> ghidra.formats.gfilesystem.crypto.CachedPasswordProvider:
        """
        Returns the {@link CachedPasswordProvider}.
         <p>
         (Used by GUI actions to manage the cache)
        @return cached crypto provider instance
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCryptoProviderInstance(self, providerClass: java.lang.Class) -> object:
        """
        Returns the previously registered matching {@link CryptoProvider} instance.
        @param <T> CryptoProvider type
        @param providerClass {@link CryptoProvider} class
        @return previously registered CryptoProvider instance, or null if not found
        """
        ...

    @staticmethod
    def getInstance() -> ghidra.formats.gfilesystem.crypto.CryptoProviders:
        """
        Fetch the global {@link CryptoProviders} singleton instance.
        @return shared {@link CryptoProviders} singleton instance
        """
        ...

    def hashCode(self) -> int: ...

    def newSession(self) -> ghidra.formats.gfilesystem.crypto.CryptoSession:
        """
        Creates a new {@link CryptoSession}.
         <p>
         TODO: to truly be effective when multiple files
         are being opened (ie. batch import), nested sessions
         need to be implemented.
        @return new {@link CryptoSession} instance
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def registerCryptoProvider(self, provider: ghidra.formats.gfilesystem.crypto.CryptoProvider) -> None:
        """
        Adds a {@link CryptoProvider} to this registry.
         <p>
         TODO: do we need provider priority ordering?
        @param provider {@link CryptoProvider}
        """
        ...

    def toString(self) -> unicode: ...

    def unregisterCryptoProvider(self, provider: ghidra.formats.gfilesystem.crypto.CryptoProvider) -> None:
        """
        Removes a {@link CryptoProvider} from this registry.
        @param provider {@link CryptoProvider} to remove
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def cachedCryptoProvider(self) -> ghidra.formats.gfilesystem.crypto.CachedPasswordProvider: ...