from typing import List
import ghidra.app.util.bin.format.dwarf4.external
import ghidra.program.model.listing
import java.lang


class ExternalDebugInfo(object):
    """
    Metadata needed to find an ELF/DWARF external debug file, retrieved from an ELF binary's
     ".gnu_debuglink" section and/or ".note.gnu.build-id" section.  
 
     The debuglink can provide a filename and crc of the external debug file, while the build-id
     can provide a hash that is converted to a filename that identifies the external debug file.
    """





    def __init__(self, filename: unicode, crc: int, hash: List[int]):
        """
        Constructor to create an {@link ExternalDebugInfo} instance.
        @param filename filename of external debug file, or null
        @param crc crc32 of external debug file, or 0 if no filename
        @param hash build-id hash digest found in ".note.gnu.build-id" section, or null if
         not present
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.dwarf4.external.ExternalDebugInfo:
        """
        Create a new {@link ExternalDebugInfo} from information found in the specified program.
        @param program {@link Program} to query
        @return new {@link ExternalDebugInfo} or null if no external debug metadata found in
         program
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCrc(self) -> int:
        """
        Return the crc of the external debug file.  Not valid if filename is missing.
        @return int crc32 of external debug file.
        """
        ...

    def getFilename(self) -> unicode:
        """
        Return the filename of the external debug file, or null if not specified.
        @return String filename of external debug file, or null if not specified
        """
        ...

    def getHash(self) -> List[int]:
        """
        Return the build-id hash digest.
        @return byte array containing the build-id hash (usually 20 bytes)
        """
        ...

    def hasFilename(self) -> bool:
        """
        Return true if there is a filename
        @return boolean true if filename is available, false if not
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
    def crc(self) -> int: ...

    @property
    def filename(self) -> unicode: ...

    @property
    def hash(self) -> List[int]: ...