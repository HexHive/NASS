from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf.info
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class NoteGnuBuildId(ghidra.app.util.bin.format.elf.info.ElfNote):
    """
    An ELF note that specifies the build-id (sha1/md5/etc hash or manually specified bytes that 
     can be hex-ified) of the containing program.
 
     The hex values of the build-id are useful to find an external debug file.
    """

    SECTION_NAME: unicode = u'.note.gnu.build-id'







    def decorateProgramInfo(self, programInfoOptions: ghidra.framework.options.Options) -> None:
        """
        Adds a single entry to the Options, built from the {@link #getProgramInfoKey()} value and
         {@link #getNoteValueString()} value.
        @param programInfoOptions {@link Options} to add entry to
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.NoteGnuBuildId:
        """
        Reads a NoteGnuBuildId from the standard ".note.gnu.build-id" section in the 
         specified Program.
        @param program Program to read from
        @return new instance, or null if not found or data error
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

    def getNoteValueString(self) -> unicode:
        """
        Returns a string representation of this note's 'value', used when creating the
          PROGRAM_INFO entry.
          <p>
          Specific Note subclasses should override this to return a better string than this default
          implementation.
        @return string describing this note's value
        """
        ...

    def getProgramInfoKey(self) -> unicode:
        """
        Returns a string that is used to build a PROGRAM_INFO entry's key.
         <p>
         Specific Note subclasses can override this to return a better key string.
        @return key string (avoid using '.' characters as they will be converted to '_'s)
        """
        ...

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
    def read(note: ghidra.app.util.bin.format.elf.info.ElfNote, program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.NoteGnuBuildId:
        """
        Deserializes a NoteGnuBuildId from an already read generic Note.
        @param note generic Note
        @param program context
        @return new NoteGnuBuildId instance, never null
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
    def noteTypeName(self) -> unicode: ...