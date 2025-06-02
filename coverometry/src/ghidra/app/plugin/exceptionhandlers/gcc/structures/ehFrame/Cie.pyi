import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import java.lang


class Cie(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    A Common Information Entry (CIE) holds information that is shared among many
     Frame Description Entries (FDEs). There is at least one CIE in every
     non-empty .debug_frame section.
 
     The structures modeled here are described in detail in the C++ ABI.
    """





    @overload
    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Creates a common information entry object that is not in the debug frame section.
         <p>Note: The <code>create(Address)</code> method must be called after constructing a 
         <code>Cie</code> to associate it with an address before any of its "process..." methods are called.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program containing the CIE.
        """
        ...

    @overload
    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, isInDebugFrame: bool):
        """
        Creates a common information entry object.
         <p>Note: The <code>create(Address)</code> method must be called after constructing a 
         <code>Cie</code> to associate it with an address before any of its "process..." methods are called.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program containing the CIE.
        @param isInDebugFrame true if this CIE is in the debug frame section
        """
        ...



    def create(self, cieAddress: ghidra.program.model.address.Address) -> None:
        """
        Creates a Common Information Entry (CIE) at <code>cieAddress</code>. 
         <br>Note: This method must get called before any of the "get..." methods.
        @param cieAddress the address where the CIE should be created.
        @throws MemoryAccessException if memory for the CIE couldn't be read.
        @throws ExceptionHandlerFrameException if some of the CIE information couldn't be created.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the address where this CIE is located in the program.
        @return the address of this CIE.
        """
        ...

    def getAugmentationString(self) -> unicode:
        """
        Gets the augmentation string which indicates optional fields and how to interpret them.
        @return the augmentation string.
        """
        ...

    def getCieId(self) -> int:
        """
        Gets the ID for this CIE record.
        @return the CIE identifier
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeAlignment(self) -> int:
        """
        Gets the value of the code alignment factor for this CIE record.
        @return the code alignment factor
        """
        ...

    def getDataAlignment(self) -> int:
        """
        Gets the value of the data alignment factor for this CIE record.
        @return the data alignment factor
        """
        ...

    def getFDEDecoder(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder:
        """
        Gets the decoder for the FDE that is associated with this CIE.
        @return the decoder for the FDE
        """
        ...

    def getFDEEncoding(self) -> int:
        """
        Gets the indicator for the FDE address pointer encoding.
        @return the FDE address pointer encoding.
        """
        ...

    def getLSDADecoder(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder:
        """
        Gets the decoder for the LSDA that is associated with this CIE.
        @return the decoder for the LSDA
        """
        ...

    def getLSDAEncoding(self) -> int:
        """
        Gets the indicator for the LSDA pointer encoding.
        @return the LSDA pointer encoding.
        """
        ...

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Method that returns the address immediately following the Common Information Entry
        @return Address immediately following the CIE
        """
        ...

    def getReturnAddressRegisterColumn(self) -> int:
        """
        Gets the return address register column for this CIE record.
        @return the return address register column
        """
        ...

    def getSegmentSize(self) -> int:
        """
        Gets the segment size for this CIE record.
        @return the segment size
        """
        ...

    def hashCode(self) -> int: ...

    def isEndOfFrame(self) -> bool:
        """
        Determines if this CIE encountered a zero length record, which indicates the end of 
         the frame.
        @return true if we are at end of frame due to encountering a zero length record.
        """
        ...

    def isInDebugFrame(self) -> bool:
        """
        Determines if this CIE is in the debug frame section.
        @return true if in the debug frame section.
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
    def FDEDecoder(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder: ...

    @property
    def FDEEncoding(self) -> int: ...

    @property
    def LSDADecoder(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder: ...

    @property
    def LSDAEncoding(self) -> int: ...

    @property
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def augmentationString(self) -> unicode: ...

    @property
    def cieId(self) -> int: ...

    @property
    def codeAlignment(self) -> int: ...

    @property
    def dataAlignment(self) -> int: ...

    @property
    def endOfFrame(self) -> bool: ...

    @property
    def inDebugFrame(self) -> bool: ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def returnAddressRegisterColumn(self) -> int: ...

    @property
    def segmentSize(self) -> int: ...