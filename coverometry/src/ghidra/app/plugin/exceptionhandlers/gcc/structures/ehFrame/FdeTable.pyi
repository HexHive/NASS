import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import java.lang


class FdeTable(object):
    """
    Class that builds the Frame Description Entry (FDE) Table for a Common Information Entry (CIE).
 
     Call Frame Instructions (taken from gcc-3.2.3-20030829/gcc/dwarf2.h
 
        DW_CFA_advance_loc = 0x40,
        DW_CFA_offset = 0x80,
        DW_CFA_restore = 0xc0,
        DW_CFA_nop = 0x00,
        DW_CFA_set_loc = 0x01,
        DW_CFA_advance_loc1 = 0x02,
        DW_CFA_advance_loc2 = 0x03,
        DW_CFA_advance_loc4 = 0x04,
        DW_CFA_offset_extended = 0x05,
        DW_CFA_restore_extended = 0x06,
        DW_CFA_undefined = 0x07,
        DW_CFA_same_value = 0x08,
        DW_CFA_register = 0x09,
        DW_CFA_remember_state = 0x0a,
        DW_CFA_restore_state = 0x0b,
        DW_CFA_def_cfa = 0x0c,
        DW_CFA_def_cfa_register = 0x0d,
        DW_CFA_def_cfa_offset = 0x0e,

        //DWARF 3. //
        DW_CFA_def_cfa_expression = 0x0f,
        DW_CFA_expression = 0x10,
        DW_CFA_offset_extended_sf = 0x11,
        DW_CFA_def_cfa_sf = 0x12,
        DW_CFA_def_cfa_offset_sf = 0x13,
 
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, curProg: ghidra.program.model.listing.Program):
        """
        Constructor for an FDE table.
        @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
        @param curProg the program containing the FDE table.
        """
        ...



    def create(self, addr: ghidra.program.model.address.Address, decoder: ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder, fdeTableCnt: long) -> None:
        """
        Creates an FDE Table at the specified Address.
        @param addr Address at which the FDE Table should be created.
        @param decoder the decoder for DWARF encoded exception handling information
        @param fdeTableCnt the number of exception handler FDEs.
        @throws MemoryAccessException if the needed memory can't be read.
        @throws ExceptionHandlerFrameException if the FDE table can't be decoded.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

