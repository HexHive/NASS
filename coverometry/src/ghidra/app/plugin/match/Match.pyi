from typing import List
import ghidra.app.plugin.match
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class Match(object, java.lang.Comparable):
    """
    Match maintains information about a single match between two programs.
     The match can consist of either bytes or code units.
    """





    @overload
    def __init__(self, thisBeginning: ghidra.program.model.address.Address, otherBeginning: ghidra.program.model.address.Address, bytes: List[int], length: int):
        """
        @param thisBeginning The start Address of the match in the program
         from which the matches are being found.
        @param otherBeginning The start Address of the match in the program
         to which the matches are being found.
        @param bytes the bytes which make up this match.
        @param length the length of the bytes array.
        """
        ...

    @overload
    def __init__(self, thisBeginning: ghidra.program.model.address.Address, otherBeginning: ghidra.program.model.address.Address, codeUnits: List[ghidra.program.model.listing.CodeUnit], otherUnits: List[ghidra.program.model.listing.CodeUnit], length: int):
        """
        @param thisBeginning The start Address of the match in the program
         from which the matches are being found.
        @param otherBeginning The start Address of the match in the program
         to which the matches are being found.
        @param codeUnits The CodeUnits which make up the match in this
         Program.
        @param otherUnits The CodeUnits which make up this match in the 
         other program. Note, the code units need no match up byte for 
         byte.
        @param length The length of the CodeUnit arrays.
        """
        ...



    @overload
    def compareTo(self, m: ghidra.app.plugin.match.Match) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    @overload
    def continueMatch(self, b: int) -> None:
        """
        @param b Continue the match by adding the additional byte b.
        """
        ...

    @overload
    def continueMatch(self, cu: ghidra.program.model.listing.CodeUnit, otherUnit: ghidra.program.model.listing.CodeUnit) -> None:
        """
        @param cu The CodeUnit which extends the match in 'this' program.
        @param otherUnit The CodeUnit which extends the match in 'the other'
         program.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def expectedAddressForNextMatch(self, baseLength: int) -> ghidra.program.model.address.Address:
        """
        @param baseLength the minimum number of items which make up a match.
         There are different values for instruction and byte matches. This
         value should either be NaiveMatchPlugin.MATCH_LENGTH_FOR_INSTRUCTIONS
         or NaiveMatchPlugin.MATCH_LENGTH_FOR_BYTES which can be found by
         calling getMatchLengthForInstructions() or getMatchLengthForBytes().
        @return The Address at which a continuing byte or code unit would
         be expected to be found in the other program.
        """
        ...

    def getBytes(self) -> List[object]:
        """
        @return array containing the objects that make up the match 
         in this program.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getOtherBeginning(self) -> ghidra.program.model.address.Address:
        """
        @return The Address that starts the match in the other program.
        """
        ...

    def getOtherBytes(self) -> List[object]:
        """
        @return array containing the objects that make up the match 
         in the other program.
        """
        ...

    def getThisBeginning(self) -> ghidra.program.model.address.Address:
        """
        @return The Address that starts the match in this program.
        """
        ...

    def hashCode(self) -> int: ...

    def length(self) -> int:
        """
        @return The number of items that make up this match.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def printMatch(self) -> unicode: ...

    def toString(self) -> unicode: ...

    def totalLength(self) -> int:
        """
        @return The total number of bytes that make up this match.
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def bytes(self) -> List[object]: ...

    @property
    def otherBeginning(self) -> ghidra.program.model.address.Address: ...

    @property
    def otherBytes(self) -> List[object]: ...

    @property
    def thisBeginning(self) -> ghidra.program.model.address.Address: ...