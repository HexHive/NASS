from typing import List
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang


class CodeUnitLocation(ghidra.program.util.ProgramLocation):
    """
    CodeUnitLocation provides information about the location
     in a program within a CodeUnit.
    """





    @overload
    def __init__(self):
        """
        Default constructor for a code unit location needed for restoring from XML.
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, row: int, col: int, charOffset: int):
        """
        Create a new <CODE>CodeUnitLocation</CODE> for the given address.
         The address will be adjusted to the beginning of the code unit containing
         that address(if it exists).  The original address can be retrieved using
         the "getByteAddress()" method.
        @param program the program for obtaining the code unit
        @param addr address of the location; should not be null
        @param row the row within the field.
        @param col - the display item index on the given row. (Note most fields only have one display item per row)
        @param charOffset - the character offset within the display item.
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: List[int], row: int, col: int, charOffset: int):
        """
        Create a new <CODE>CodeUnitLocation</CODE> for the given address.
         The address will be adjusted to the beginning of the code unit containing
         that address(if it exists).  The original address can be retrieved using
         the "getByteAddress()" method.
        @param program the program for obtaining the code unit
        @param addr address of the location; should not be null
        @param componentPath if this is not null it is the path to a data
         component inside of another data component
        @param row the row within the field.
        @param col - the display item index on the given row. (Note most fields only have one display item per row)
        @param charOffset - the character offset within the display item.
        """
        ...



    @overload
    def compareTo(self, other: ghidra.program.util.ProgramLocation) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, obj: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address associated with this location.

         <p>
         Note: this may not be the same as the byte address. For example, in a {@link CodeUnit code
         unit} location this may be the minimum address of the code unit that contains the byte
         address.
        @return the address.
        """
        ...

    def getByteAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the byte level address associated with this location.
        @return the byte address.
        """
        ...

    def getCharOffset(self) -> int:
        """
        Returns the character offset in the display item at the (row,col).
        @return the character offset in the display item at the (row,col).
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getColumn(self) -> int:
        """
        Returns the column index of the display piece represented by this location. For most
         locations, there is only one display item per row, in which case this value will be 0.
        @return the column.
        """
        ...

    def getComponentPath(self) -> List[int]:
        """
        Returns the componentPath for the {@link CodeUnit code unit}. Null will be returned if the
         object is an {@link Instruction} or a top-level {@link Data} object.
        @return the path.
        """
        ...

    @staticmethod
    def getLocation(program: ghidra.program.model.listing.Program, saveState: ghidra.framework.options.SaveState) -> ghidra.program.util.ProgramLocation:
        """
        Get the program location for the given program and save state object.
        @param program the program for the location
        @param saveState the state to restore
        @return the restored program location
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program associated with this location.
        @return the program.
        """
        ...

    def getRefAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the "referred to" address if the location is over an address in some field.
        @return the address.
        """
        ...

    def getRow(self) -> int:
        """
        Returns the row within the program location.
        @return the row within the program location.
        """
        ...

    def hashCode(self) -> int: ...

    def isValid(self, p: ghidra.program.model.listing.Program) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def restoreState(self, program1: ghidra.program.model.listing.Program, obj: ghidra.framework.options.SaveState) -> None:
        """
        Restore this program location using the given program and save state object.
        @param program1 program to restore from
        @param obj the save state to restore from
        """
        ...

    def saveState(self, obj: ghidra.framework.options.SaveState) -> None:
        """
        Save this program location to the given save state object.
        @param obj the save state object for saving the location
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

