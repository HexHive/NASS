from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.task
import java.lang


class DyldCacheHeader(object, ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_header structure.
    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new {@link DyldCacheHeader}.
        @param reader A {@link BinaryReader} positioned at the start of a DYLD cache header
        @throws IOException if there was an IO-related problem creating the DYLD cache header
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getArchitecture(self) -> ghidra.app.util.bin.format.macho.dyld.DyldArchitecture:
        """
        Gets architecture information.
        @return architecture information
        """
        ...

    def getBaseAddress(self) -> long:
        """
        Gets the base address of the DYLD cache.  This is where the cache should be loaded in
         memory.
        @return The base address of the DYLD cache
        """
        ...

    def getBranchPoolAddresses(self) -> List[long]:
        """
        Gets the {@link List} of branch pool address.  Requires header to have been parsed.
        @return The {@link List} of branch pool address
        """
        ...

    def getCacheMappingAndSlideInfos(self) -> List[ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingAndSlideInfo]:
        """
        Gets the {@link List} of {@link DyldCacheMappingAndSlideInfo}s.  Requires header to have been parsed.
        @return The {@link List} of {@link DyldCacheMappingAndSlideInfo}s
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getEntryPoint(self) -> long:
        """
        Gets the DYLD entry point address (if known)
        @return The DYLD entry point address, or null if it is not known
        """
        ...

    def getImagesCount(self) -> int:
        """
        Gets the number of {@link DyldCacheImageInfo}s.
        @return The number of {@link DyldCacheImageInfo}s
        """
        ...

    def getImagesOffset(self) -> int:
        """
        Gets the file offset to first {@link DyldCacheImageInfo}.
        @return The file offset to first {@link DyldCacheImageInfo}
        """
        ...

    def getLocalSymbolsInfo(self) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo:
        """
        Gets the {@link DyldCacheLocalSymbolsInfo}.
        @return The {@link DyldCacheLocalSymbolsInfo}.  Could be be null if it didn't parse.
        """
        ...

    def getMagic(self) -> List[int]:
        """
        Gets the magic bytes, which contain version information.
        @return The magic bytes
        """
        ...

    def getMappedImages(self) -> List[ghidra.app.util.bin.format.macho.dyld.DyldCacheImage]:
        """
        Generates a {@link List} of {@link DyldCacheImage}s that are mapped in by this 
         {@link DyldCacheHeader}.  Requires header to have been parsed.
         <p>
         NOTE: A DYLD subcache header may declare an image, but that image may get loaded at an
         address defined by the memory map of a different subcache header.  This method will only 
         return the images that are mapped by "this" header's memory map.
        @return A {@link List} of {@link DyldCacheImage}s mapped by this {@link DyldCacheHeader}
        """
        ...

    def getMappingInfos(self) -> List[ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo]:
        """
        Gets the {@link List} of {@link DyldCacheMappingInfo}s.  Requires header to have been parsed.
        @return The {@link List} of {@link DyldCacheMappingInfo}s
        """
        ...

    def getSlideInfos(self) -> List[ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfoCommon]:
        """
        Gets the {@link List} of {@link DyldCacheSlideInfoCommon}s.
        @return the {@link List} of {@link DyldCacheSlideInfoCommon}s.
        """
        ...

    def getSubcacheEntries(self) -> List[ghidra.app.util.bin.format.macho.dyld.DyldSubcacheEntry]:
        """
        Gets the {@link List} of {@link DyldSubcacheEntry}s.  Requires header to have been parsed.
        @return The {@link List} of {@link DyldSubcacheEntry}s
        """
        ...

    def getSymbolFileUUID(self) -> unicode:
        """
        Gets the symbol file UUID in {@link String} form
        @return The symbol file UUID in {@link String} form, or null if a symbol file UUID is not 
            defined or is all zeros
        """
        ...

    def getUUID(self) -> unicode:
        """
        Gets the UUID in {@link String} form
        @return The UUID in {@link String} form, or null if a UUID is not defined
        """
        ...

    def hasAccelerateInfo(self) -> bool:
        """
        Checks to see whether or not the old accelerate info fields are being used
        @return True if the old accelerate info fields are being used; otherwise, false if the new
           dyldInCache fields are being used
        """
        ...

    def hasSlideInfo(self) -> bool:
        """
        Checks to see if any slide info exists
        @return True if any slide info exists; otherwise, false
        """
        ...

    def hashCode(self) -> int: ...

    def isSubcache(self) -> bool:
        """
        Checks to see whether or not this is a subcache
        @return True if this is a subcache; otherwise, false if it's a base cache
        """
        ...

    def markup(self, program: ghidra.program.model.listing.Program, markupLocalSymbols: bool, space: ghidra.program.model.address.AddressSpace, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Marks up this {@link DyldCacheHeader} with data structures and comments.
        @param program The {@link Program} to mark up
        @param markupLocalSymbols True if the local symbols should be marked up; otherwise, false
        @param space The {@link Program}'s {@link AddressSpace}
        @param monitor A cancellable task monitor
        @param log The log
        @throws CancelledException if the user cancelled the operation
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parseFromFile(self, parseLocalSymbols: bool, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Parses the structures referenced by this {@link DyldCacheHeader} from a file.
        @param parseLocalSymbols True if local symbols should be parsed; otherwise, false
        @param log The log
        @param monitor A cancellable task monitor
        @throws CancelledException if the user cancelled the operation
        """
        ...

    def parseFromMemory(self, program: ghidra.program.model.listing.Program, space: ghidra.program.model.address.AddressSpace, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Parses the structures referenced by this {@link DyldCacheHeader} from memory.
        @param program The {@link Program} whose memory to parse
        @param space The {@link Program}'s {@link AddressSpace}
        @param log The log
        @param monitor A cancellable task monitor
        @throws CancelledException if the user cancelled the operation
        """
        ...

    def parseLocalSymbolsInfo(self, shouldParse: bool, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def setFileBlock(self, block: ghidra.program.model.mem.MemoryBlock) -> None:
        """
        Sets the {@link MemoryBlock} associated with this header's FILE block.
        @param block The {@link MemoryBlock} associated with this header's FILE block
        """
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    def unslidLoadAddress(self) -> long:
        """
        Get the original unslid load address.  This is found in the first mapping infos.
        @return the original unslid load address
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def UUID(self) -> unicode: ...

    @property
    def architecture(self) -> ghidra.app.util.bin.format.macho.dyld.DyldArchitecture: ...

    @property
    def baseAddress(self) -> long: ...

    @property
    def branchPoolAddresses(self) -> List[object]: ...

    @property
    def cacheMappingAndSlideInfos(self) -> List[object]: ...

    @property
    def entryPoint(self) -> long: ...

    @property
    def fileBlock(self) -> None: ...  # No getter available.

    @fileBlock.setter
    def fileBlock(self, value: ghidra.program.model.mem.MemoryBlock) -> None: ...

    @property
    def imagesCount(self) -> int: ...

    @property
    def imagesOffset(self) -> int: ...

    @property
    def localSymbolsInfo(self) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo: ...

    @property
    def magic(self) -> List[int]: ...

    @property
    def mappedImages(self) -> List[object]: ...

    @property
    def mappingInfos(self) -> List[object]: ...

    @property
    def slideInfos(self) -> List[object]: ...

    @property
    def subcache(self) -> bool: ...

    @property
    def subcacheEntries(self) -> List[object]: ...

    @property
    def symbolFileUUID(self) -> unicode: ...