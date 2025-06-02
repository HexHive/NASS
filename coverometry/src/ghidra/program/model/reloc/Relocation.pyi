from typing import List
import ghidra.program.model.address
import ghidra.program.model.reloc
import ghidra.program.model.reloc.Relocation
import java.lang
import java.util


class Relocation(object):
    """
    A class to store the information needed for a single
     program relocation.
    """






    class Status(java.lang.Enum):
        APPLIED: ghidra.program.model.reloc.Relocation.Status = APPLIED
        APPLIED_OTHER: ghidra.program.model.reloc.Relocation.Status = APPLIED_OTHER
        FAILURE: ghidra.program.model.reloc.Relocation.Status = FAILURE
        PARTIAL: ghidra.program.model.reloc.Relocation.Status = PARTIAL
        SKIPPED: ghidra.program.model.reloc.Relocation.Status = SKIPPED
        UNKNOWN: ghidra.program.model.reloc.Relocation.Status = UNKNOWN
        UNSUPPORTED: ghidra.program.model.reloc.Relocation.Status = UNSUPPORTED







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        @staticmethod
        def getStatus(__a0: int) -> ghidra.program.model.reloc.Relocation.Status: ...

        def getValue(self) -> int: ...

        def hasBytes(self) -> bool: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.program.model.reloc.Relocation.Status: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.program.model.reloc.Relocation.Status]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def value(self) -> int: ...

    def __init__(self, addr: ghidra.program.model.address.Address, status: ghidra.program.model.reloc.Relocation.Status, type: int, values: List[long], bytes: List[int], symbolName: unicode):
        """
        Constructs a new relocation.
        @param addr the address where the relocation is required
        @param status relocation status
        @param type the type of relocation to perform
        @param values the values needed when performing the relocation.  Definition of values is
         specific to loader used and relocation type.
        @param bytes original instruction bytes affected by relocation
        @param symbolName the name of the symbol being relocated
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address where the relocation is required.
        @return the address where the relocation is required
        """
        ...

    def getBytes(self) -> List[int]:
        """
        Returns the original instruction bytes affected by applied relocation.
        @return original instruction bytes affected by relocation if it was successfully applied
         (i.e., {@link Status#APPLIED}, {@link Status#APPLIED_OTHER}), otherwise null may be returned.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getLength(self) -> int:
        """
        Returns the number of original instruction bytes affected by applied relocation.
        @return number of original instruction bytes affected by relocation if it was successfully applied
         (i.e., {@link Status#APPLIED}, {@link Status#APPLIED_OTHER}), otherwise null may be returned.
        """
        ...

    def getStatus(self) -> ghidra.program.model.reloc.Relocation.Status:
        """
        Return the relocation's application status within the program.
        @return relocation's application status within the program.
        """
        ...

    def getSymbolName(self) -> unicode:
        """
        The name of the symbol being relocated or <code>null</code> if there is no symbol name.
        @return the name of the symbol being relocated or <code>null</code> if there is no symbol name.
        """
        ...

    def getType(self) -> int:
        """
        Returns the type of the relocation to perform.
        @return the type of the relocation to perform
        """
        ...

    def getValues(self) -> List[long]:
        """
        Returns the value needed when performing the relocation.
        @return the value needed when performing the relocation
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
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def bytes(self) -> List[int]: ...

    @property
    def length(self) -> int: ...

    @property
    def status(self) -> ghidra.program.model.reloc.Relocation.Status: ...

    @property
    def symbolName(self) -> unicode: ...

    @property
    def type(self) -> int: ...

    @property
    def values(self) -> List[long]: ...