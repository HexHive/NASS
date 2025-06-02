from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.FileCache
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.formats.gfilesystem.crypto
import ghidra.util.task
import java.io
import java.lang


class FileSystemService(object):
    """
    Provides methods for dealing with GFilesystem files and GFileSystem.
 
     Most methods take FSRL references to files as a way to decouple dependencies and
     reduce forced filesystem instantiation.
 
     (ie. a GFile instance is only valid if its GFileSystem is open, which
     means that its parent probably also has to be open, recursively, etc, whereas a FSRL
     is always valid and does not force the instantiation of parent objects)
 
     GFileSystem should be used via FileSystemRef
     handles that ensure the filesystem is pinned in memory and won't be closed while
     you are using it.
 
     If you are working with GFile instances, you should have a
     FileSystemRef that you are using to pin the filesystem.
 
     Files written to the  directory are obfuscated to prevent interference from
     virus scanners.  See ObfuscatedInputStream or ObfuscatedOutputStream or 
     ObfuscatedFileByteProvider.
  
     Thread-safe.
 
    """






    class DerivedStreamPushProducer(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def push(self, __a0: java.io.OutputStream) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class DerivedStreamProducer(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def produceDerivedStream(self) -> java.io.InputStream: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    @overload
    def __init__(self):
        """
        Creates a FilesystemService instance, using the {@link Application}'s default value
         for {@link Application#getUserCacheDirectory() user cache directory} as the
         cache directory.
        """
        ...

    @overload
    def __init__(self, fscacheDir: java.io.File):
        """
        Creates a FilesystemService instance, using the supplied directory as its file caching
         root directory.
        @param fscacheDir {@link File Root dir} to use to store files placed into cache.
        """
        ...



    def clear(self) -> None:
        """
        Forcefully closes all open filesystems and clears caches.
        """
        ...

    def closeUnusedFileSystems(self) -> None:
        """
        Close unused filesystems.
        """
        ...

    def createPlaintextTempFile(self, provider: ghidra.app.util.bin.ByteProvider, filenamePrefix: unicode, monitor: ghidra.util.task.TaskMonitor) -> java.io.File:
        """
        Exports the bytes in a {@link ByteProvider} into normal {@link File} that can be
         used as the caller wishes.
         <p>
         This method is labeled as 'plaintext' to differentiate it from the standard obfuscated 
         temp files that are produced by this service.
        @param provider {@link ByteProvider} that will be written to a temp file
        @param filenamePrefix filename prefix of the newly created File
        @param monitor {@link TaskMonitor}
        @return temporary {@link File}
        @throws IOException if error copying data or if cancelled
        """
        ...

    def createTempFile(self, sizeHint: long) -> ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder:
        """
        Returns a {@link FileCacheEntryBuilder} that will allow the caller to
         write bytes to it.
         <p>
         After calling {@link FileCacheEntryBuilder#finish() finish()},
         the caller will have a {@link FileCacheEntry} that can provide access to a
         {@link ByteProvider}.
         <p>
         Temporary files that are written to disk are obfuscated to avoid interference from
         overzealous virus scanners.  See {@link ObfuscatedInputStream} / 
         {@link ObfuscatedOutputStream}.
         <p>
        @param sizeHint the expected size of the file, or -1 if unknown
        @return {@link FileCacheEntryBuilder} that must be finalized by calling 
         {@link FileCacheEntryBuilder#finish() finish()}
        @throws IOException if error
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAllFilesystemNames(self) -> List[unicode]:
        """
        Returns a list of all detected GFilesystem filesystem names.
         <p>
         See {@link FileSystemFactoryMgr#getAllFilesystemNames()}.
        @return {@link List} of strings.
        """
        ...

    def getByteProvider(self, fsrl: ghidra.formats.gfilesystem.FSRL, fullyQualifiedFSRL: bool, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a {@link ByteProvider} with the contents of the requested {@link GFile file}.
         <p>
         Never returns null, throws IOException if there was a problem.
         <p>
         Caller is responsible for {@link ByteProvider#close() closing()} the ByteProvider
         when finished.
        @param fsrl {@link FSRL} file to wrap
        @param fullyQualifiedFSRL if true, the returned ByteProvider's FSRL will always have a MD5
         hash
        @param monitor {@link TaskMonitor} to watch and update
        @return new {@link ByteProvider}
        @throws CancelledException if user cancels
        @throws IOException if IO problem
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDerivedByteProvider(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, derivedFSRL: ghidra.formats.gfilesystem.FSRL, derivedName: unicode, sizeHint: long, producer: ghidra.formats.gfilesystem.FileSystemService.DerivedStreamProducer, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a {@link ByteProvider} that contains the
         derived (ie. decompressed or decrypted) contents of the requested file.
         <p>
         The resulting ByteProvider will be a cached file, either written to a 
         temporary file, or a in-memory buffer if small enough (see {@link FileCache#MAX_INMEM_FILESIZE}).
         <p> 
         If the file was not present in the cache, the {@link DerivedStreamProducer producer}
         will be called and it will be responsible for returning an {@link InputStream}
         which has the derived contents, which will be added to the file cache for next time.
         <p>
        @param containerFSRL {@link FSRL} w/hash of the source (or container) file that this 
         derived file is based on
        @param derivedFSRL (optional) {@link FSRL} to assign to the resulting ByteProvider
        @param derivedName a unique string identifying the derived file inside the source (or container) file
        @param sizeHint the expected size of the resulting ByteProvider, or -1 if unknown
        @param producer supplies an InputStream if needed.  See {@link DerivedStreamProducer}
        @param monitor {@link TaskMonitor} that will be monitor for cancel requests and updated
         with file io progress
        @return a {@link ByteProvider} containing the bytes of the requested file, that has the 
         specified derivedFSRL, or a pseudo FSRL if not specified.  Never null
        @throws CancelledException if the user cancels
        @throws IOException if there was an io error
        """
        ...

    def getDerivedByteProviderPush(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, derivedFSRL: ghidra.formats.gfilesystem.FSRL, derivedName: unicode, sizeHint: long, pusher: ghidra.formats.gfilesystem.FileSystemService.DerivedStreamPushProducer, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a {@link ByteProvider} that contains the
         derived (ie. decompressed or decrypted) contents of the requested file.
         <p>
         The resulting ByteProvider will be a cached file, either written to a 
         temporary file, or a in-memory buffer if small enough (see {@link FileCache#MAX_INMEM_FILESIZE}).
         <p> 
         If the file was not present in the cache, the {@link DerivedStreamPushProducer pusher}
         will be called and it will be responsible for producing and writing the derived
         file's bytes to a {@link OutputStream}, which will be added to the file cache for next time.
         <p>
        @param containerFSRL {@link FSRL} w/hash of the source (or container) file that this 
         derived file is based on
        @param derivedFSRL (optional) {@link FSRL} to assign to the resulting ByteProvider
        @param derivedName a unique string identifying the derived file inside the source (or container) file
        @param sizeHint the expected size of the resulting ByteProvider, or -1 if unknown
        @param pusher writes bytes to the supplied OutputStream.  See {@link DerivedStreamPushProducer}
        @param monitor {@link TaskMonitor} that will be monitor for cancel requests and updated
         with file io progress
        @return a {@link ByteProvider} containing the bytes of the requested file, that has the 
         specified derivedFSRL, or a pseudo FSRL if not specified.  Never null
        @throws CancelledException if the user cancels
        @throws IOException if there was an io error
        """
        ...

    def getFileIfAvailable(self, provider: ghidra.app.util.bin.ByteProvider) -> java.io.File:
        """
        Converts a {@link ByteProvider} to the underlying File that contains the contents of
         the ByteProvider.
         <p>
         Returns {@code null} if the underlying file is not available.
        @param provider {@link ByteProvider}
        @return a java {@link File} that is providing the bytes of the specified ByteProvider,
         or null if there is no available file
        """
        ...

    def getFilesystem(self, fsFSRL: ghidra.formats.gfilesystem.FSRLRoot, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FileSystemRef:
        """
        Returns a filesystem instance for the requested {@link FSRLRoot}, either from an already
         loaded instance in the global fscache, or by instantiating the requested filesystem
         from its container file (in a possibly recursive manner, depending on the depth
         of the FSLR)
         <p>
         Never returns NULL, instead throws IOException if there is a problem.
         <p>
         The caller is responsible for releasing the {@link FileSystemRef}.
         <p>
        @param fsFSRL {@link FSRLRoot} of file system you want a reference to.
        @param monitor {@link TaskMonitor} to allow the user to cancel.
        @return a new {@link FileSystemRef} that the caller is responsible for closing when
         no longer needed, never {@code null}.
        @throws IOException if there was an io problem.
        @throws CancelledException if the user cancels.
        """
        ...

    def getFullyQualifiedFSRL(self, fsrl: ghidra.formats.gfilesystem.FSRL, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns a cloned copy of the {@code FSRL} that should have MD5 values specified.
         (excluding GFile objects that don't have data streams)
         <p>
        @param fsrl {@link FSRL} of the file that should be forced to have a MD5
        @param monitor {@link TaskMonitor} to watch and update with progress.
        @return possibly new {@link FSRL} instance with a MD5 value.
        @throws CancelledException if user cancels.
        @throws IOException if IO problem.
        """
        ...

    @staticmethod
    def getInstance() -> ghidra.formats.gfilesystem.FileSystemService: ...

    def getLocalFS(self) -> ghidra.formats.gfilesystem.LocalFileSystem:
        """
        Returns a direct reference to the {@link LocalFileSystem local filesystem}.
        @return A direct reference to the {@link LocalFileSystem local filesystem}.
        """
        ...

    def getLocalFSRL(self, f: java.io.File) -> ghidra.formats.gfilesystem.FSRL:
        """
        Builds a {@link FSRL} of a {@link File file} located on the local filesystem.
        @param f {@link File} on the local filesystem
        @return {@link FSRL} pointing to the same file, never null
        """
        ...

    def getMountedFilesystem(self, fsFSRL: ghidra.formats.gfilesystem.FSRLRoot) -> ghidra.formats.gfilesystem.FileSystemRef:
        """
        Returns a new FilesystemRef handle to an already mounted filesystem.
         <p>
         The caller is responsible for releasing the ref.
         <p>
         Returns null if there is no filesystem mounted at {@code fsFSRL}.
        @param fsFSRL {@link FSRLRoot} of file system to get a {@link FileSystemRef} to.
        @return new {@link FileSystemRef} or null if requested file system not mounted.
        """
        ...

    def getMountedFilesystems(self) -> List[ghidra.formats.gfilesystem.FSRLRoot]:
        """
        Returns a list of all currently mounted filesystems.
         <p>
         As a FSRL is returned, there is no guarantee that the filesystem will still be
         mounted when you later use values from the list.
         <p>
        @return {@link List} of {@link FSRLRoot} of currently mounted filesystems.
        """
        ...

    def getNamedTempFile(self, tempFileCacheEntry: ghidra.formats.gfilesystem.FileCache.FileCacheEntry, name: unicode) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a {@link ByteProvider} for the specified {@link FileCacheEntry}, using the
         specified filename.
         <p>
         The returned ByteProvider's FSRL will be decorative and does not allow returning to
         the same ByteProvider at a later time.
        @param tempFileCacheEntry {@link FileCacheEntry} (returned by {@link #createTempFile(long)})
        @param name desired name
        @return new {@link ByteProvider} with decorative {@link FSRL}
        @throws IOException if io error
        """
        ...

    def getRefdFile(self, fsrl: ghidra.formats.gfilesystem.FSRL, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.RefdFile:
        """
        Returns the {@link GFile} pointed to by the FSRL, along with a {@link FileSystemRef}
         that the caller is responsible for releasing (either explicitly via
         {@code result.fsRef.close()} or via the {@link RefdFile#close()}).
        @param fsrl {@link FSRL} of the desired file
        @param monitor {@link TaskMonitor} so the user can cancel
        @return a {@link RefdFile} which contains the resultant {@link GFile} and a
         {@link FileSystemRef} that needs to be closed, or {@code null} if the filesystem
         does not have the requested file.
        @throws CancelledException if the user cancels
        @throws IOException if there was a file io problem
        """
        ...

    def hasDerivedFile(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, derivedName: unicode, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Returns true if the specified derived file exists in the file cache.
        @param containerFSRL {@link FSRL} w/hash of the container
        @param derivedName name of the derived file inside of the container
        @param monitor {@link TaskMonitor}
        @return boolean true if file exists at time of query, false if file is not in cache
        @throws CancelledException if user cancels
        @throws IOException if other IO error
        """
        ...

    def hashCode(self) -> int: ...

    def isFileFilesystemContainer(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Returns true if the container file probably holds one of the currently supported
         filesystem types.
         <p>
        @param containerFSRL {@link FSRL} of the file being queried.
        @param monitor {@link TaskMonitor} to watch and update progress.
        @return boolean true if the file probably is a container, false otherwise.
        @throws CancelledException if user cancels.
        @throws IOException if IO problem.
        """
        ...

    def isFilesystemMountedAt(self, fsrl: ghidra.formats.gfilesystem.FSRL) -> bool:
        """
        Returns true of there is a {@link GFileSystem filesystem} mounted at the requested
         {@link FSRL} location.
        @param fsrl {@link FSRL} container to query for mounted filesystem
        @return boolean true if filesystem mounted at location.
        """
        ...

    @staticmethod
    def isInitialized() -> bool:
        """
        Returns true if this service has been loaded
        @return true if this service has been loaded
        """
        ...

    def isLocal(self, fsrl: ghidra.formats.gfilesystem.FSRL) -> bool:
        """
        Returns true if the specified location is a path on the local computer's
         filesystem.
        @param fsrl {@link FSRL} path to query
        @return true if local, false if the path points to an embedded file in a container.
        """
        ...

    def mountSpecificFileSystem(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, fsClass: java.lang.Class, monitor: ghidra.util.task.TaskMonitor) -> FSTYPE:
        """
        Mount a specific file system (by class) using a specified container file.
         <p>
         The newly constructed / mounted file system is not managed by this FileSystemService
         or controlled with {@link FileSystemRef}s.
         <p>
         The caller is responsible for closing the resultant file system instance when it is
         no longer needed.
         <p>
        @param containerFSRL a reference to the file that contains the file system image
        @param fsClass the GFileSystem derived class that implements the specific file system
        @param monitor {@link TaskMonitor} to allow the user to cancel
        @return new {@link GFileSystem} instance, caller is responsible for closing() when done.
        @throws CancelledException if user cancels
        @throws IOException if file io error or wrong file system type.
        """
        ...

    def newCryptoSession(self) -> ghidra.formats.gfilesystem.crypto.CryptoSession:
        """
        Returns a new {@link CryptoSession} that the caller can use to query for
         passwords and such.  Caller is responsible for closing the instance when done.
         <p>
         Later callers to this method will receive a nested CryptoSession that shares it's
         state with the initial CryptoSession, until the initial CryptoSession is closed().
        @return new {@link CryptoSession} instance, never null
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openFileSystemContainer(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.GFileSystem:
        """
        Open the file system contained at the specified location.
         <p>
         The newly constructed / mounted file system is not managed by this FileSystemService
         or controlled with {@link FileSystemRef}s.
         <p>
         The caller is responsible for closing the resultant file system instance when it is
         no longer needed.
         <p>
        @param containerFSRL a reference to the file that contains the file system image
        @param monitor {@link TaskMonitor} to allow the user to cancel
        @return new {@link GFileSystem} instance, caller is responsible for closing() when done.
        @throws CancelledException if user cancels
        @throws IOException if file io error or wrong file system type.
        """
        ...

    @overload
    def probeFileForFilesystem(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, monitor: ghidra.util.task.TaskMonitor, conflictResolver: ghidra.formats.gfilesystem.FileSystemProbeConflictResolver) -> ghidra.formats.gfilesystem.FileSystemRef:
        """
        Auto-detects a filesystem in the container file pointed to by the FSRL.
         <p>
         Returns a filesystem instance for the requested container file, either from an already
         loaded instance in the Global fs cache, or by probing for a filesystem in the container
         file using the {@link FileSystemFactoryMgr}.
         <p>
         Returns null if no filesystem implementation was found that could handle the container
         file.
        @param containerFSRL {@link FSRL} of the file container
        @param monitor {@link TaskMonitor} to watch and update progress.
        @param conflictResolver {@link FileSystemProbeConflictResolver} to handle choosing
         the correct file system type among multiple results, or null if you want
         {@link FileSystemProbeConflictResolver#CHOOSEFIRST} .
        @return new {@link FileSystemRef} or null
        @throws CancelledException if user cancels.
        @throws IOException if IO problem.
        """
        ...

    @overload
    def probeFileForFilesystem(self, containerFSRL: ghidra.formats.gfilesystem.FSRL, monitor: ghidra.util.task.TaskMonitor, conflictResolver: ghidra.formats.gfilesystem.FileSystemProbeConflictResolver, priorityFilter: int) -> ghidra.formats.gfilesystem.FileSystemRef:
        """
        Auto-detects a filesystem in the container file pointed to by the FSRL.
         <p>
         Returns a filesystem instance for the requested container file, either from an already
         loaded instance in the Global fs cache, or by probing for a filesystem in the container
         file using a {@link FileSystemFactoryMgr}.
         <p>
         Returns null if no filesystem implementation was found that could handle the container
         file.
        @param containerFSRL {@link FSRL} of the file container
        @param monitor {@link TaskMonitor} to watch and update progress.
        @param conflictResolver {@link FileSystemProbeConflictResolver} to handle choosing
         the correct file system type among multiple results, or null if you want
         {@link FileSystemProbeConflictResolver#CHOOSEFIRST} .
        @param priorityFilter minimum filesystem {@link FileSystemInfo#priority()} to allow
         when using file system factories to probe the container.
        @return new {@link FileSystemRef} or null
        @throws CancelledException if user cancels.
        @throws IOException if IO problem.
        """
        ...

    def pushFileToCache(self, file: java.io.File, fsrl: ghidra.formats.gfilesystem.FSRL, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Adds a plaintext (non-obfuscated) file to the cache, consuming it in the process, and returns
         a {@link ByteProvider} that contains the contents of the file.
         <p>
         NOTE: only use this if you have no other choice and are forced to deal with already
         existing files in the local filesystem.
        @param file {@link File} to add
        @param fsrl {@link FSRL} of the file that is being added
        @param monitor {@link TaskMonitor}
        @return {@link ByteProvider} (hosted in the FileCache) that contains the bytes of the
         specified file
        @throws CancelledException if cancelled
        @throws IOException if error
        """
        ...

    def releaseFileCache(self, fsrl: ghidra.formats.gfilesystem.FSRL) -> None:
        """
        Allows the resources used by caching the specified file to be released.
        @param fsrl {@link FSRL} file to release cache resources for
        """
        ...

    def releaseFileSystemImmediate(self, fsRef: ghidra.formats.gfilesystem.FileSystemRef) -> None:
        """
        Releases the specified {@link FileSystemRef}, and if no other references remain, removes 
         it from the shared cache of file system instances.
        @param fsRef the ref to release
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def allFilesystemNames(self) -> List[object]: ...

    @property
    def localFS(self) -> ghidra.formats.gfilesystem.LocalFileSystem: ...

    @property
    def mountedFilesystems(self) -> List[object]: ...