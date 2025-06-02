from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.importer
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class DyldCacheSlideInfoCommon(object, ghidra.app.util.bin.StructConverter):
    """
    Class for representing the common components of the various dyld_cache_slide_info structures.
     The intent is for the the full dyld_cache_slide_info structures to extend this and add their
     specific parts.
    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    BYTES_PER_CHAIN_OFFSET: int = 4
    CHAIN_OFFSET_MASK: int = 16383
    DATA_PAGE_MAP_ENTRY: int = 1
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



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, mappingAddress: long, mappingSize: long, mappingFileOffset: long):
        """
        Create a new {@link DyldCacheSlideInfoCommon}.
        @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info
        @param mappingAddress The base address of where the slide fixups will take place
        @param mappingSize The size of the slide fixups block
        @param mappingFileOffset The base file offset of where the slide fixups will take place
        @throws IOException if there was an IO-related problem creating the DYLD slide info
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def fixupSlidePointers(self, program: ghidra.program.model.listing.Program, markup: bool, addRelocations: bool, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Fixes up the programs slide pointers
        @param program The {@link Program}
        @param markup True if the slide pointers should be marked up; otherwise, false
        @param addRelocations True if slide pointer locations should be added to the relocation
           table; otherwise, false
        @param log The log
        @param monitor A cancellable monitor
        @throws MemoryAccessException If there was a problem accessing memory
        @throws CancelledException If the user cancelled the operation
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getMappingAddress(self) -> long:
        """
        {@return The base address of where the slide fixups will take place}
        """
        ...

    def getMappingFileOffset(self) -> long:
        """
        {@return The base file offset of where the slide fixups will take place}
        """
        ...

    def getMappingSize(self) -> long:
        """
        {@return The size of the slide fixups block}
        """
        ...

    def getSlideFixups(self, reader: ghidra.app.util.bin.BinaryReader, pointerSize: int, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> List[ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideFixup]:
        """
        Walks the slide fixup information and collects a {@link List} of {@link DyldCacheSlideFixup}s
         that will need to be applied to the image
        @param reader A {@link BinaryReader} positioned at the start of the segment to fix up
        @param pointerSize The size of a pointer in bytes
        @param log The log
        @param monitor A cancellable monitor
        @return A {@link List} of {@link DyldCacheSlideFixup}s
        @throws IOException If there was an IO-related issue
        @throws CancelledException If the user cancelled the operation
        """
        ...

    def getSlideInfoOffset(self) -> long:
        """
        {@return The original slide info offset}
        """
        ...

    def getVersion(self) -> int:
        """
        {@return The version of the DYLD slide info}
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def parseSlideInfo(reader: ghidra.app.util.bin.BinaryReader, slideInfoOffset: long, mappingAddress: long, mappingSize: long, mappingFileOffset: long, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfoCommon:
        """
        Parses the slide info
        @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info
        @param slideInfoOffset The offset of the slide info to parse
        @param mappingAddress The base address of where the slide fixups will take place
        @param mappingSize The size of the slide fixups block
        @param mappingFileOffset The base file offset of where the slide fixups will take place
        @param log The log
        @param monitor A cancelable task monitor
        @return The slide info object
        """
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def mappingAddress(self) -> long: ...

    @property
    def mappingFileOffset(self) -> long: ...

    @property
    def mappingSize(self) -> long: ...

    @property
    def slideInfoOffset(self) -> long: ...

    @property
    def version(self) -> int: ...