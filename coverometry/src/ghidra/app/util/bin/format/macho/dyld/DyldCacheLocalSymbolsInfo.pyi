from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.commands
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class DyldCacheLocalSymbolsInfo(object, ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_local_symbols_info structure.
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



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, architecture: ghidra.app.util.bin.format.macho.dyld.DyldArchitecture, use64bitOffsets: bool):
        """
        Create a new {@link DyldCacheLocalSymbolsInfo}.
        @param reader A {@link BinaryReader} positioned at the start of a DYLD local symbols info
        @param architecture The {@link DyldArchitecture}
        @param use64bitOffsets True if the DYLD local symbol entries use 64-bit dylib offsets; false
           if they use 32-bit
        @throws IOException if there was an IO-related problem creating the DYLD local symbols info
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLocalSymbolsEntries(self) -> List[ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsEntry]:
        """
        Gets the {@link List} of {@link DyldCacheLocalSymbolsEntry}s.
        @return The {@link List} of {@link DyldCacheLocalSymbolsEntry}
        """
        ...

    @overload
    def getNList(self) -> List[ghidra.app.util.bin.format.macho.commands.NList]:
        """
        Gets the {@link List} of {@link NList}.
        @return The {@link List} of {@link NList}
        """
        ...

    @overload
    def getNList(self, dylibOffset: long) -> List[ghidra.app.util.bin.format.macho.commands.NList]:
        """
        Gets the {@link List} of {@link NList} for the given dylib offset.
        @param dylibOffset The offset of dylib in the DYLD Cache
        @return The {@link List} of {@link NList} for the given dylib offset
        """
        ...

    def hashCode(self) -> int: ...

    def markup(self, program: ghidra.program.model.listing.Program, localSymbolsInfoAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Marks up this {@link DyldCacheLocalSymbolsInfo} with data structures and comments.
        @param program The {@link Program} to mark up
        @param localSymbolsInfoAddr The {@link Address} of the {@link DyldCacheLocalSymbolsInfo}
        @param monitor A cancellable task monitor
        @param log The log
        @throws CancelledException if the user cancelled the operation
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parse(self, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Parses the structures referenced by this {@link DyldCacheLocalSymbolsInfo}.
        @param log The log
        @param monitor A cancellable task monitor
        @throws CancelledException if the user cancelled the operation
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
    def NList(self) -> List[object]: ...

    @property
    def localSymbolsEntries(self) -> List[object]: ...