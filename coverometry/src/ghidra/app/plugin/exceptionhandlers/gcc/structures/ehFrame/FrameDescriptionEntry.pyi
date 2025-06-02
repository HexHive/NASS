from typing import List
import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import java.lang


class FrameDescriptionEntry(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    A Frame Description Entry (FDE) describes the 
     stack call frame, in particular, how to restore
     registers.
 
     Taken from binutils-2.14.90.0.4/bfd/elf-bfd.h
 
     struct eh_cie_fde { 
     		unsigned int offset; 
     		unsigned int size; 
     		asection *sec;
     		unsigned int new_offset; 
     		unsigned char fde_encoding; 
     		unsigned char *lsda_encoding; 
     		unsigned char lsda_offset; 
     		unsigned char cie : 1; 
     		unsigned char removed : 1; 
     		unsigned char make_relative : 1; 
     		unsigned char make_lsda_relative : 1; 
     		unsigned char per_encoding_relative : 1; 
     };
 
 
     ACTUAL: struct eh_cie_fde { 
     		dword fde.length 
     		dword fde.ciePointer (Offset to this FDEs CIE) 
     		dword fde.pcBegin 
     		dword fde.pcRange 
     		dword fde.augmentationLength 
     		dword fde.augmentationData 
     		dword Call Frame Instructions dword 
     		!!! NO IDEA !!! 
     }
 
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, cieSource: ghidra.app.plugin.exceptionhandlers.gcc.sections.CieSource):
        """
        Constructor for a frame descriptor entry.
         <br>Note: The <code>create(Address)</code> method must be called after constructing a 
         <code>FrameDescriptionEntry</code> to associate it with an address before any of its 
         "get..." methods are called.
        @param monitor a status monitor for tracking progress and allowing cancelling when creating
         an FDE.
        @param program the program where this will create an FDE.
        @param cieSource the call frame information entry for this FDE.
        """
        ...



    def create(self, fdeBaseAddress: ghidra.program.model.address.Address) -> ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor:
        """
        Creates a Frame Description Entry (FDE) at the address
         specified.
         <br>Note: This method must get called before any of the "get..." methods.
        @param fdeBaseAddress Address where the FDE should be created.
        @return a region descriptor which holds information about this FDE. Otherwise, null.
        @throws MemoryAccessException if memory for the FDE or its associated data can't be accessed
        @throws ExceptionHandlerFrameException if there is an error creating the FDE information.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAugmentationData(self) -> List[int]:
        """
        Gets the bytes which specify the FDE field that refers to the augmentation data.
        @return the FDE record's augmentation data.
        """
        ...

    def getAugmentationDataAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the augmentation data in this FDE record.
        @return the augmentation data field's address
        """
        ...

    def getAugmentationExData(self) -> List[int]:
        """
        Gets the call frame augmentation data that indicates how registers are saved and restored.
        @return the augmentation data
        """
        ...

    def getAugmentationExDataAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the start address for the call frame augmentation data.
        @return the address of the call frame augmentation data
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the next address in memory after this FDE record.
        @return the next address after this FDE or null if at the end of the section
        """
        ...

    def getProtectionRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the address range that contains the program instructions.
        @return the address range
        """
        ...

    def hashCode(self) -> int: ...

    def isEndOfFrame(self) -> bool:
        """
        Determines if this FDE encountered a zero length record, which indicates the end of 
         the frame.
        @return true if we are at end of frame due to encountering a zero length record.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setAugmentationDataExLength(self, len: int) -> int:
        """
        Sets the value this region descriptor maintains to indicate the length of the 
         augmentation data.
        @param len number of bytes that compose the augmentation data
        @return the length of the augmentation data or -1 if it has already been set.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def augmentationData(self) -> List[int]: ...

    @property
    def augmentationDataAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def augmentationDataExLength(self) -> None: ...  # No getter available.

    @augmentationDataExLength.setter
    def augmentationDataExLength(self, value: int) -> None: ...

    @property
    def augmentationExData(self) -> List[int]: ...

    @property
    def augmentationExDataAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def endOfFrame(self) -> bool: ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def protectionRange(self) -> ghidra.program.model.address.AddressRange: ...