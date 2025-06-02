from typing import List
import ghidra.app.util.bin.format.macho.commands.dyld.BindingTable
import java.lang


class BindingTable(object):
    """
    A Mach-O binding table
    """






    class Binding(object):




        @overload
        def __init__(self): ...

        @overload
        def __init__(self, __a0: ghidra.app.util.bin.format.macho.commands.dyld.BindingTable.Binding): ...



        def equals(self, __a0: object) -> bool: ...

        def getAddend(self) -> long: ...

        def getClass(self) -> java.lang.Class: ...

        def getLibraryOrdinal(self) -> int: ...

        def getSegmentIndex(self) -> int: ...

        def getSegmentOffset(self) -> long: ...

        def getSymbolName(self) -> unicode: ...

        def getType(self) -> int: ...

        def getUnknownOpcode(self) -> int: ...

        def hashCode(self) -> int: ...

        def isWeak(self) -> bool: ...

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
        def addend(self) -> long: ...

        @property
        def libraryOrdinal(self) -> int: ...

        @property
        def segmentIndex(self) -> int: ...

        @property
        def segmentOffset(self) -> long: ...

        @property
        def symbolName(self) -> unicode: ...

        @property
        def type(self) -> int: ...

        @property
        def unknownOpcode(self) -> int: ...

        @property
        def weak(self) -> bool: ...

    @overload
    def __init__(self):
        """
        Creates an empty {@link BindingTable}
        """
        ...

    @overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader, tableSize: int, lazy: bool):
        """
        Creates and parses a new {@link BindingTable}
        @param reader A {@link BinaryReader reader} positioned at the start of the binding table
        @param header The header
        @param tableSize The size of the table, in bytes
        @param lazy True if this is a lazy binding table; otherwise, false
        @throws IOException if an IO-related error occurs while parsing
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getBindings(self) -> List[ghidra.app.util.bin.format.macho.commands.dyld.BindingTable.Binding]:
        """
        {@return the bindings}
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getOpcodeOffsets(self) -> List[long]:
        """
        {@return opcode offsets from the start of the bind data}
        """
        ...

    def getSlebOffsets(self) -> List[long]:
        """
        {@return SLEB128 offsets from the start of the bind data}
        """
        ...

    def getStringOffsets(self) -> List[long]:
        """
        {@return string offsets from the start of the bind data}
        """
        ...

    def getThreadedBindings(self) -> List[ghidra.app.util.bin.format.macho.commands.dyld.BindingTable.Binding]:
        """
        {@return the threaded bindings, or null if threaded bindings are not being used}
        """
        ...

    def getUlebOffsets(self) -> List[long]:
        """
        {@return ULEB128 offsets from the start of the bind data}
        """
        ...

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

    @property
    def bindings(self) -> List[object]: ...

    @property
    def opcodeOffsets(self) -> List[object]: ...

    @property
    def slebOffsets(self) -> List[object]: ...

    @property
    def stringOffsets(self) -> List[object]: ...

    @property
    def threadedBindings(self) -> List[object]: ...

    @property
    def ulebOffsets(self) -> List[object]: ...