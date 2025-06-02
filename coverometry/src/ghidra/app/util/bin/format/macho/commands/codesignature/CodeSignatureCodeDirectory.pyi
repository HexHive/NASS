import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands.codesignature
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class CodeSignatureCodeDirectory(ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureGenericBlob):
    """
    Represents a CS_BlobIndex structure
    """





    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new {@link CodeSignatureCodeDirectory}
        @param reader A {@link BinaryReader} positioned at the start of the structure
        @throws IOException if there was an IO-related problem creating the structure
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLength(self) -> int:
        """
        {@return the length}
        """
        ...

    def getMagic(self) -> int:
        """
        {@return the magic}
        """
        ...

    def hashCode(self) -> int: ...

    def markup(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, header: ghidra.app.util.bin.format.macho.MachHeader, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None: ...

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

