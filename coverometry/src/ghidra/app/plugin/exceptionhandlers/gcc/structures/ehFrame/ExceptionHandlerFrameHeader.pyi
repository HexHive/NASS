import ghidra.program.model.address
import java.lang


class ExceptionHandlerFrameHeader(object):
    """
    This class represents an Exception Handler Frame Header.
 
     struct eh_frame_hdr {
         unsigned char eh_frame_header_version
         unsigned char eh_frame_pointer_encoding
         unsigned char eh_frame_description_entry_count
         unsigned_char eh_handler_table_encoding
     }
 
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, curProg: ghidra.program.model.listing.Program):
        """
        Constructor for an ExceptionHandlerFrameHeader.
        @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
        @param curProg the program containing this eh frame header.
        """
        ...



    def addToDataTypeManager(self) -> None:
        """
        Adds the structure data type for the eh frame header to the program's data type manager.
        """
        ...

    def create(self, addr: ghidra.program.model.address.Address) -> None:
        """
        Method that creates an Exception Handler Frame Header Structure
         at the address specified by 'addr'. If addr is 'null', this method returns without creating
         the structure.
        @param addr - Address at which the Exception Handler Frame Header Structure should be created.
        @throws AddressOutOfBoundsException if the memory needed for this frame header isn't in the program.
        @throws MemoryAccessException if the memory needed for this frame header isn't in the program.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getEh_FrameDescEntryCntEncoding(self) -> int:
        """
        Gets the eh frame description entry count.
        @return the description entry count.
        """
        ...

    def getEh_FramePtrEncoding(self) -> int:
        """
        Gets the eh frame pointer encoding.
        @return the pointer encoding.
        """
        ...

    def getEh_FrameTableEncoding(self) -> int:
        """
        Gets the eh handler table encoding.
        @return the table encoding.
        """
        ...

    def getEh_FrameVersion(self) -> int:
        """
        Gets the version for this program's eh frame.
        @return the version indicator.
        """
        ...

    def getLength(self) -> int:
        """
        Gets the length of the EH Frame Header.
        @return the length of this frame header.
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
    def eh_FrameDescEntryCntEncoding(self) -> int: ...

    @property
    def eh_FramePtrEncoding(self) -> int: ...

    @property
    def eh_FrameTableEncoding(self) -> int: ...

    @property
    def eh_FrameVersion(self) -> int: ...

    @property
    def length(self) -> int: ...