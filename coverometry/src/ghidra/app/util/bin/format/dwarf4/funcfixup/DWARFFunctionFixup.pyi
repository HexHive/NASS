from typing import List
import ghidra.app.util.bin.format.dwarf4.funcfixup
import ghidra.app.util.bin.format.dwarf4.next
import ghidra.program.model.listing
import ghidra.util.classfinder
import java.lang


class DWARFFunctionFixup(ghidra.util.classfinder.ExtensionPoint, object):
    """
    Interface for add-in logic to fix/modify/tweak DWARF functions before they are written 
     to the Ghidra program.
 
     Use  to
     control the order of evaluation (higher numbers are run earlier).
 
     Fixups are found using ClassSearcher, and their class names must end
     in "DWARFFunctionFixup" (see ExtensionPoint.manifest).
    """

    PRIORITY_LAST: int = 1000
    PRIORITY_NORMAL: int = 3000
    PRIORITY_NORMAL_EARLY: int = 4000
    PRIORITY_NORMAL_LATE: int = 2000







    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findFixups() -> List[ghidra.app.util.bin.format.dwarf4.funcfixup.DWARFFunctionFixup]:
        """
        Return a list of all current {@link DWARFFunctionFixup fixups} found in the classpath
         by ClassSearcher.
        @return list of all current fixups found in the classpath
        """
        ...

    def fixupDWARFFunction(self, dfunc: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction, gfunc: ghidra.program.model.listing.Function) -> None:
        """
        Called before a {@link DWARFFunction} is used to create a Ghidra Function.
         <p>
         If processing of the function should terminate (and the function be skipped), throw
         a {@link DWARFException}.
        @param dfunc {@link DWARFFunction} info read from DWARF about the function
        @param gfunc the Ghidra {@link Function} that will receive the DWARF information
        """
        ...

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

