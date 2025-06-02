import ghidra.app.util.bin
import ghidra.app.util.bin.format.golang
import ghidra.app.util.bin.format.golang.rtti
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class GoPcHeader(object):
    """
    A low-level structure embedded in golang binaries that contains useful bootstrapping
     information.
 
    """

    GOPCLNTAB_SECTION_NAME: unicode = u'.gopclntab'
    GO_1_16_MAGIC: int = -6
    GO_1_18_MAGIC: int = -16
    GO_1_2_MAGIC: int = -5



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findPclntabAddress(programContext: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper, range: ghidra.program.model.address.AddressRange, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        Searches (possibly slowly) for a pclntab structure in the specified memory range, which
         is typically necessary in stripped PE binaries.
        @param programContext {@link GoRttiMapper}
        @param range memory range to search (typically .rdata or .noptrdata sections)
        @param monitor {@link TaskMonitor} that will let the user cancel
        @return {@link Address} of the found pclntab structure, or null if not found
        @throws IOException if error reading
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCuAddress(self) -> ghidra.program.model.address.Address: ...

    def getFiletabAddress(self) -> ghidra.program.model.address.Address: ...

    def getFuncnameAddress(self) -> ghidra.program.model.address.Address: ...

    def getGoVersion(self) -> ghidra.app.util.bin.format.golang.GoVer: ...

    def getPclnAddress(self) -> ghidra.program.model.address.Address: ...

    @staticmethod
    def getPclntabAddress(program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        Returns the {@link Address} (if present) of the go pclntab section or symbol.
        @param program {@link Program}
        @return {@link Address} of go pclntab, or null if not present
        """
        ...

    def getPctabAddress(self) -> ghidra.program.model.address.Address: ...

    def getTextStart(self) -> ghidra.program.model.address.Address: ...

    @staticmethod
    def hasPclntab(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the specified program has an easily found pclntab
        @param program {@link Program}
        @return boolean true if program has a pclntab, false otherwise
        """
        ...

    def hasTextStart(self) -> bool: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isPclntab(provider: ghidra.app.util.bin.ByteProvider) -> bool:
        """
        Returns true if there is a pclntab at the current position of the specified ByteProvider.
        @param provider {@link ByteProvider}
        @return boolean true if the byte provider has the magic signature of a pclntab
        @throws IOException if error reading
        """
        ...

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
    def cuAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def filetabAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def funcnameAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def goVersion(self) -> ghidra.app.util.bin.format.golang.GoVer: ...

    @property
    def pclnAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def pctabAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def textStart(self) -> ghidra.program.model.address.Address: ...