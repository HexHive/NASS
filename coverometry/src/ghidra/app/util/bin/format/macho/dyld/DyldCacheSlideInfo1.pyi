from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.importer
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class DyldCacheSlideInfo1(ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfoCommon):
    """
    Represents a dyld_cache_slide_info structure.
 
     Seen in iOS 8 and earlier.
    """





    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, mappingAddress: long, mappingSize: long, mappingFileOffset: long):
        """
        Create a new {@link DyldCacheSlideInfo1}.
        @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 1
        @param mappingAddress The base address of where the slide fixups will take place
        @param mappingSize The size of the slide fixups block
        @param mappingFileOffset The base file offset of where the slide fixups will take place
        @throws IOException if there was an IO-related problem creating the DYLD slide info 1
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

    def getEntries(self) -> List[int]:
        """
        {@return The entries}
        """
        ...

    def getEntriesCount(self) -> int:
        """
        {@return The entries count}
        """
        ...

    def getEntriesOffset(self) -> int:
        """
        {@return The entries offset}
        """
        ...

    def getEntriesSize(self) -> int:
        """
        {@return The entries size}
        """
        ...

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

    def getSlideFixups(self, reader: ghidra.app.util.bin.BinaryReader, pointerSize: int, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> List[ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideFixup]: ...

    def getSlideInfoOffset(self) -> long:
        """
        {@return The original slide info offset}
        """
        ...

    def getToc(self) -> List[int]:
        """
        {@return The TOC}
        """
        ...

    def getTocCount(self) -> int:
        """
        {@return The TOC count}
        """
        ...

    def getTocOffset(self) -> int:
        """
        {@return The TOC offset}
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
    def entries(self) -> List[int]: ...

    @property
    def entriesCount(self) -> int: ...

    @property
    def entriesOffset(self) -> int: ...

    @property
    def entriesSize(self) -> int: ...

    @property
    def toc(self) -> List[int]: ...

    @property
    def tocCount(self) -> int: ...

    @property
    def tocOffset(self) -> int: ...