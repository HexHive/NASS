import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf.info
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class GnuDebugLink(object, ghidra.app.util.bin.format.elf.info.ElfInfoItem):
    """
    An ELF section (almost like a ElfNote) that contains information about an external
     DWARF debug file.
 
     External DWARF debug files can also be specified with a NoteGnuBuildId.
    """

    SECTION_NAME: unicode = u'.gnu_debuglink'



    def __init__(self, filenameLen: int, filename: unicode, crc: int): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.GnuDebugLink:
        """
        Reads a GnuDebugLink from the standard ".gnu_debuglink" section in the specified Program.
        @param program Program to read from
        @return new instance, or null if not found or data error
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCrc(self) -> int: ...

    def getFilename(self) -> unicode: ...

    def getFilenameLen(self) -> int: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def markupElfInfoItemSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> None: ...

    def markupProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(br: ghidra.app.util.bin.BinaryReader, program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.GnuDebugLink:
        """
        Reads a GnuDebugLink from the specified BinaryReader.
        @param br BinaryReader to read from
        @param program unused, present to match the signature of {@link ElfInfoItem.ReaderFunc}
        @return new instance, or null if data error
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
    def crc(self) -> int: ...

    @property
    def filename(self) -> unicode: ...

    @property
    def filenameLen(self) -> int: ...