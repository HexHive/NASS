from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import java.io
import java.lang


class FileCache(object):
    """
    File caching implementation.
 
     Caches files based on a hash of the contents of the file.
     Files are retrieved using the hash string.
     Cached files are stored in a file with a name that is the hex encoded value of the hash.
     Cached files are obfuscated/de-obfuscated when written/read to/from disk.  See 
     ObfuscatedFileByteProvider, ObfuscatedInputStream, 
     ObfuscatedOutputStream.
     Cached files are organized into a nested directory structure to prevent
     overwhelming a single directory with thousands of files.
 
     Nested directory structure is based on the file's name:
        File: AABBCCDDEEFF...  AA/AABBCCDDEEFF...
 
     Cache size is not bounded.
 
     Cache maintenance is done during startup if interval since last maintenance has been exceeded.
 
     Files are not removed from the cache after being added, except during startup maintenance.
    """

    MAX_INMEM_FILESIZE: int = 2097152
    MD5_HEXSTR_LEN: int = 32




    class FileCacheEntry(object):








        def asByteProvider(self, __a0: ghidra.formats.gfilesystem.FSRL) -> ghidra.app.util.bin.ByteProvider: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getMD5(self) -> unicode: ...

        def hashCode(self) -> int: ...

        def length(self) -> long: ...

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
        def MD5(self) -> unicode: ...




    class FileCacheEntryBuilder(java.io.OutputStream):








        def close(self) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        def finish(self) -> ghidra.formats.gfilesystem.FileCache.FileCacheEntry: ...

        def flush(self) -> None: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        @staticmethod
        def nullOutputStream() -> java.io.OutputStream: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @overload
        def write(self, __a0: int) -> None: ...

        @overload
        def write(self, __a0: List[int]) -> None: ...

        @overload
        def write(self, __a0: List[int], __a1: int, __a2: int) -> None: ...



    def __init__(self, cacheDir: java.io.File):
        """
        Creates a new {@link FileCache} instance where files are stored under the specified
         {@code cacheDir}
         <p>
        @param cacheDir where to store the files
        @throws IOException if there was a problem creating subdirectories under cacheDir or
         when pruning expired files.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def performCacheMaintOnOldDirIfNeeded(oldCacheDir: java.io.File) -> None:
        """
        Backwards compatible with previous cache directories to age off the files located
         therein.
        @param oldCacheDir the old 2-level cache directory
        @deprecated Marked as deprecated to ensure this is removed in a few versions after most
         user's old-style cache dirs have been cleaned up.
        """
        ...

    def purge(self) -> None:
        """
        Deletes all stored files from this file cache that are under a "NN" two hex digit
         nesting dir.
         <p>
         Will cause other processes which are accessing or updating the cache to error.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

