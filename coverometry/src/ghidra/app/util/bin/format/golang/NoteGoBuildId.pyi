from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf.info
import ghidra.app.util.bin.format.golang
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class NoteGoBuildId(ghidra.app.util.bin.format.elf.info.ElfNote):
    """
    An ELF note that specifies the golang build-id.
    """

    SECTION_NAME: unicode = u'.note.go.buildid'



    def __init__(self, nameLen: int, name: unicode, vendorType: int, description: List[int]): ...



    def decorateProgramInfo(self, programInfoOptions: ghidra.framework.options.Options) -> None:
        """
        Adds a single entry to the Options, built from the {@link #getProgramInfoKey()} value and
         {@link #getNoteValueString()} value.
        @param programInfoOptions {@link Options} to add entry to
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBuildId(self) -> unicode:
        """
        Returns the go buildid value
        @return go buildid value
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> List[int]:
        """
        Returns the bytes in the description portion of the note.
        @return byte array
        """
        ...

    def getDescriptionAsHexString(self) -> unicode:
        """
        Returns a hex string of the description bytes.
        @return hex string
        """
        ...

    def getDescriptionLen(self) -> int: ...

    def getDescriptionReader(self, isLittleEndian: bool) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns a {@link BinaryReader} that reads from this note's description blob.
        @param isLittleEndian flag, see {@link BinaryReader#BinaryReader(ByteProvider, boolean)}
        @return new BinaryReader
        """
        ...

    def getName(self) -> unicode:
        """
        Returns the name value of this note.
        @return string name
        """
        ...

    def getNameLen(self) -> int: ...

    def getNoteTypeName(self) -> unicode: ...

    def getNoteValueString(self) -> unicode: ...

    def getProgramInfoKey(self) -> unicode: ...

    def getVendorType(self) -> int:
        """
        Returns the vendor type 'enum' value of this note.
        @return vendor type 'enum' value
        """
        ...

    def hashCode(self) -> int: ...

    def isGnu(self) -> bool:
        """
        Shortcut test of name == "GNU"
        @return true if name is "GNU"
        """
        ...

    @staticmethod
    def markupElfInfoItemSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> None: ...

    def markupProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader) -> ghidra.app.util.bin.format.elf.info.ElfNote:
        """
        Reads a generic {@link ElfNote} instance from the supplied BinaryReader.
        @param reader BinaryReader to read from
        @return new {@link ElfNote} instance, never null
        @throws IOException if bad data or error reading
        """
        ...

    @overload
    @staticmethod
    def read(br: ghidra.app.util.bin.BinaryReader, unusedProgram: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.golang.NoteGoBuildId:
        """
        Reads a NoteGoBuildId from the specified BinaryReader, matching the signature of 
         ElfInfoItem.ReaderFunc.
        @param br BinaryReader
        @param unusedProgram context (unused but needed to match signature)
        @return new NoteGoBuildId instance, never null
        @throws IOException if data error
        """
        ...

    @staticmethod
    def readItemFromSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress: ...

    def toString(self) -> unicode: ...

    def toStructure(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.StructureDataType: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def buildId(self) -> unicode: ...

    @property
    def noteTypeName(self) -> unicode: ...

    @property
    def noteValueString(self) -> unicode: ...

    @property
    def programInfoKey(self) -> unicode: ...