import ghidra.app.util.bin.format.elf
import ghidra.app.util.bin.format.elf.relocation
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.reloc
import ghidra.util.classfinder
import java.lang
import java.util


class ElfRelocationHandler(object, ghidra.util.classfinder.ExtensionPoint):
    """
    ElfRelocationHandler provides the base class for processor specific
     ELF relocation handlers.
    """

    GOT_BLOCK_NAME: unicode = u'%got'



    def __init__(self): ...



    @staticmethod
    def applyComponentOffsetPointer(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentOffset: long) -> None:
        """
        Apply a pointer-typedef with a specified component-offset if specified address
         is not contained within an execute block.
        @param program program
        @param addr address where data should be applied
        @param componentOffset component offset
        """
        ...

    def canRelocate(self, elf: ghidra.app.util.bin.format.elf.ElfHeader) -> bool: ...

    def createRelocationContext(self, loadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, symbolMap: java.util.Map) -> ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext:
        """
        Relocation context for a specific Elf image and relocation table.  The relocation context
         is used to process relocations and manage any data required to process relocations.
        @param loadHelper Elf load helper
        @param symbolMap Elf symbol placement map
        @return relocation context or null if unsupported
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getRelrRelocationType(self) -> int:
        """
        Get the architecture-specific relative relocation type 
         which should be applied to RELR relocations.  The
         default implementation returns 0 which indicates 
         RELR is unsupported.
        @return RELR relocation type
        """
        ...

    def hashCode(self) -> int: ...

    @overload
    @staticmethod
    def markAsError(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: long, symbolName: unicode, msg: unicode, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Generate error log entry and bookmark at relocationAddress where
         import failed to be applied.
        @param program program
        @param relocationAddress relocation address to be bookmarked
        @param type relocation type
        @param symbolName associated symbol name
        @param msg error messge
        @param log import log
        """
        ...

    @overload
    @staticmethod
    def markAsError(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: unicode, symbolName: unicode, msg: unicode, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Generate error log entry and bookmark at relocationAddress where
         import failed to be applied.
        @param program program
        @param relocationAddress relocation address to be bookmarked
        @param type relocation type
        @param symbolName associated symbol name
        @param msg additional error message
        @param log import log
        """
        ...

    @staticmethod
    def markAsUnhandled(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: long, symbolIndex: long, symbolName: unicode, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Generate error log entry and bookmark at relocationAddress indicating 
         an unhandled relocation.
        @param program program
        @param relocationAddress relocation address to be bookmarked
        @param type relocation type
        @param symbolIndex associated symbol index within symbol table
        @param symbolName associated symbol name
        @param log import log
        """
        ...

    @staticmethod
    def markAsUninitializedMemory(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: long, symbolIndex: long, symbolName: unicode, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Generate error log entry and bookmark at relocationAddress where
         import failed to transition block to initialized while processing relocation.
        @param program program
        @param relocationAddress relocation address to be bookmarked
        @param type relocation type
        @param symbolIndex associated symbol index within symbol table
        @param symbolName associated symbol name
        @param log import log
        """
        ...

    @staticmethod
    def markAsUnsupportedRelr(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address) -> None:
        """
        Generate error log entry and bookmark at relocationAddress indicating 
         an unsupported RELR relocation.
        @param program program
        @param relocationAddress relocation address to be bookmarked
        """
        ...

    @overload
    @staticmethod
    def markAsWarning(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: unicode, msg: unicode, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Generate warning log entry and bookmark at relocationAddress where
         import issue occurred.
        @param program program
        @param relocationAddress relocation address to be bookmarked
        @param type relocation type
        @param msg message associated with warning
        @param log import log
        """
        ...

    @overload
    @staticmethod
    def markAsWarning(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, type: unicode, symbolName: unicode, symbolIndex: long, msg: unicode, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Generate warning log entry and bookmark at relocationAddress where
         import issue occurred.
        @param program program
        @param relocationAddress relocation address to be bookmarked
        @param type relocation type
        @param symbolName symbol name
        @param symbolIndex symbol index
        @param msg message associated with warning
        @param log import log
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def relocate(self, elfRelocationContext: ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext, relocation: ghidra.app.util.bin.format.elf.ElfRelocation, relocationAddress: ghidra.program.model.address.Address) -> ghidra.program.model.reloc.RelocationResult:
        """
        Perform relocation fixup
        @param elfRelocationContext relocation context
        @param relocation ELF relocation
        @param relocationAddress relocation target address (fixup location)
        @return applied relocation result (conveys status and applied byte-length)
        @throws MemoryAccessException memory access failure
        @throws NotFoundException required relocation data not found
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @staticmethod
    def warnExternalOffsetRelocation(program: ghidra.program.model.listing.Program, relocationAddress: ghidra.program.model.address.Address, symbolAddr: ghidra.program.model.address.Address, symbolName: unicode, adjustment: long, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Determine if symbolAddr is contained within the EXTERNAL block with a non-zero adjustment.  
         If so, relocationAddress will be marked with a <code>EXTERNAL Data Elf Relocation with pointer-offset</code> 
         warning or error bookmark.  Bookmark and logged message will be conveyed as an error if 
         relocationAddress resides within an executable memory block.
         NOTE: This method should only be invoked when the symbol offset will be adjusted with a non-zero 
         value (i.e., addend).
        @param program program
        @param relocationAddress relocation address to be bookmarked if EXTERNAL block relocation
        @param symbolAddr symbol address correspondng to relocation (may be null)
        @param symbolName symbol name (may not be null if symbolAddr is not null)
        @param adjustment relocation symbol offset adjustment/addend
        @param log import log
        """
        ...

    @property
    def relrRelocationType(self) -> int: ...