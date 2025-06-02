import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf.info
import ghidra.app.util.bin.format.elf.info.ElfInfoItem
import ghidra.app.util.bin.format.golang
import ghidra.program.model.address
import ghidra.program.model.listing
import java.io
import java.lang


class PEGoBuildId(object, ghidra.app.util.bin.format.elf.info.ElfInfoItem):
    """
    Similar to NoteGoBuildId, but re-implemented here because of the different
     serialization used in PE binaries.  (the logic about the buildid payload is trivial so
     there is no worry about duplicating code)
 
    """





    def __init__(self, buildId: unicode): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findBuildId(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress: ...

    def getBuildId(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def markupElfInfoItemSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> None: ...

    def markupProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    @staticmethod
    def read(is_: java.io.InputStream) -> ghidra.app.util.bin.format.golang.PEGoBuildId:
        """
        Attempts to read a PEGoBuildId from the specified InputStream (useful for early compiler
         detection before file is loaded).
        @param is {@link InputStream} providing access to the ".text" section of a PE binary
        @return PEGoBuildId instance, or null if not present
        """
        ...

    @overload
    @staticmethod
    def read(br: ghidra.app.util.bin.BinaryReader, program_notused: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.golang.PEGoBuildId:
        """
        Attempts to read a PEGoBuildId from the specified stream.
        @param br BinaryReader stream (typically the beginning of the ".text" section)
        @param program_notused not used, but needed to match functional interface
        @return PEGoBuildId instance, or null if not present
        """
        ...

    @staticmethod
    def readItemFromSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def buildId(self) -> unicode: ...