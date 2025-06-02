import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands.chained
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class DyldChainedFixupHeader(object, ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_chained_fixups_header structure.
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
        Creates a new {@link DyldChainedFixupHeader}
        @param reader A {@link BinaryReader} positioned at the start of the structure
        @throws IOException if there was an IO-related problem creating the structure
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getChainedImports(self) -> ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImports: ...

    def getChainedStartsInImage(self) -> ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsInImage: ...

    def getClass(self) -> java.lang.Class: ...

    def getFixupsVersion(self) -> int: ...

    def getImportsCount(self) -> int: ...

    def getImportsFormat(self) -> int: ...

    def getImportsOffset(self) -> int: ...

    def getStartsOffset(self) -> int: ...

    def getSymbolsFormat(self) -> int: ...

    def getSymbolsOffset(self) -> int: ...

    def hashCode(self) -> int: ...

    def isCompress(self) -> bool: ...

    def markup(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, header: ghidra.app.util.bin.format.macho.MachHeader, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Marks up this data structure with data structures and comments
        @param program The {@link Program} to mark up
        @param address The {@link Address} of this data structure
        @param header The Mach-O header
        @param monitor A cancellable task monitor
        @param log The log
        @throws CancelledException if the user cancelled the operation
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def chainedImports(self) -> ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImports: ...

    @property
    def chainedStartsInImage(self) -> ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsInImage: ...

    @property
    def compress(self) -> bool: ...

    @property
    def fixupsVersion(self) -> int: ...

    @property
    def importsCount(self) -> int: ...

    @property
    def importsFormat(self) -> int: ...

    @property
    def importsOffset(self) -> int: ...

    @property
    def startsOffset(self) -> int: ...

    @property
    def symbolsFormat(self) -> int: ...

    @property
    def symbolsOffset(self) -> int: ...