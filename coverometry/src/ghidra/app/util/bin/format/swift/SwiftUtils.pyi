from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.swift
import ghidra.program.model.listing
import ghidra.program.model.mem
import java.lang


class SwiftUtils(object):
    """
    Swift-related utility methods
    """

    PTR_RELATIVE: ghidra.program.model.data.PointerTypedef = PointerTypedef: pointer32 __((relative))
    PTR_STRING: ghidra.program.model.data.PointerTypedef = PointerTypedef: string *32 __((relative))



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getSwiftBlocks(section: ghidra.app.util.bin.format.swift.SwiftSection, program: ghidra.program.model.listing.Program) -> List[ghidra.program.model.mem.MemoryBlock]:
        """
        Gets a {@link List} of {@link MemoryBlock}s that match the given {@link SwiftSection}
        @param section The {@link SwiftSection}
        @param program The {@link Program}
        @return A {@link List} of {@link MemoryBlock}s that match the given {@link SwiftSection}
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isSwift(program: ghidra.program.model.listing.Program) -> bool:
        """
        Checks if the given {@link Program} is a Swift program
        @param program The {@link Program} to check
        @return True if the given {@link Program} is a Swift program; otherwise, false
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def relativeString(reader: ghidra.app.util.bin.BinaryReader) -> unicode:
        """
        Reads the integer at the current index and uses it as a relative pointer to read and
         return a string at that location.  When the read completes, the {@link BinaryReader} will
         be positioned directly after the initial relative pointer that was read.
        @param reader A {@link BinaryReader} positioned at the start of relative string pointer
        @return The read string
        @throws IOException if there was an IO-related problem during the reads
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

